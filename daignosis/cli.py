from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path

from daignosis.clickhouse import MetricSink
from daignosis.egress import GUARD
from daignosis.kafka_source import iter_kafka
from daignosis.pipeline import Pipeline, open_source
from daignosis.qvac_explain import Explainer
from daignosis.server import serve
from daignosis.state import AppState


def _resolve_sdk_dir() -> str | None:
    sdk_dir = os.environ.get("QVAC_SDK_DIR")
    if sdk_dir and Path(sdk_dir).is_dir():
        return sdk_dir
    for base in [Path(os.environ.get("APPDATA", "")), Path.home() / "AppData" / "Roaming"]:
        candidate = base / "npm" / "node_modules" / "@qvac" / "sdk"
        if (candidate / "dist" / "src" / "worker" / "index.js").exists():
            return str(candidate)
    return None


def _default_data() -> Path | None:
    root = Path(__file__).resolve().parents[1].parent
    candidate = root / "LogsDNSQueries 2" / "LogsDNSQueries"
    return candidate if candidate.is_dir() else None


def cmd_demo(args: argparse.Namespace) -> int:
    data = Path(args.data) if args.data else _default_data()
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    var = Path(args.var)
    var.mkdir(parents=True, exist_ok=True)
    if not args.no_airgap:
        GUARD.install()
    state = AppState()
    if args.kafka:
        topics = args.topic or ["dns-queries"]
        for hostport in args.kafka.split(","):
            GUARD.allow(hostport.split(":")[0].strip())
        state.source = f"kafka:{args.kafka}#{','.join(topics)}"
        source = iter_kafka(args.kafka, topics, group=args.group)
    else:
        state.source = str(data) if data and data.exists() else "synthetic-benign+inject"
        source = open_source(data if data and data.exists() else None, args.file)
    explainer = Explainer(cache_dir=cache, enabled=not args.no_qvac)
    sink = MetricSink(url=args.clickhouse, var_dir=var)
    pipe = Pipeline(state=state, explainer=explainer, sink=sink, batch_size=args.batch)
    httpd = serve(state, args.host, args.port)
    t_http = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    t_http.start()
    print(f"dAIgnosis http://{args.host}:{args.port}  source={state.source}", flush=True)
    try:
        pipe.run(source)
    finally:
        pipe.stop = True
        httpd.shutdown()
        GUARD.restore()
    return 0


def cmd_prefetch(args: argparse.Namespace) -> int:
    import asyncio

    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)

    async def go() -> None:
        from tetherto.qvac_sdk import Client, load_model, unload_model
        from tetherto.qvac_sdk.models import QWEN3_600M_INST_Q4

        kwargs: dict = {"config": {"cacheDirectory": str(cache.resolve())}}
        sd = _resolve_sdk_dir()
        if sd:
            kwargs["sdk_dir"] = sd
        async with Client(**kwargs) as client:
            mid = await load_model(
                client.transport,
                model_src=QWEN3_600M_INST_Q4,
                model_config={"ctx_size": 2048},
            )
            print(f"model ready: {mid}", flush=True)
            await unload_model(client.transport, mid)

    try:
        asyncio.run(go())
    except Exception as exc:
        print(f"prefetch failed: {exc}", file=sys.stderr)
        print("pip install tetherto-qvac-sdk && python -m tetherto.qvac_sdk install-worker", file=sys.stderr)
        return 1
    return 0


def cmd_airgap(args: argparse.Namespace) -> int:
    GUARD.install()
    try:
        import socket

        socket.create_connection(("1.1.1.1", 443), timeout=1)
        print("FAIL: connection to 1.1.1.1 was allowed", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"PASS: {exc}")
        return 0
    except OSError as exc:
        print(f"PASS (blocked by stack): {exc}")
        return 0
    finally:
        GUARD.restore()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="daignosis")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo")
    d.add_argument("--data", default=None)
    d.add_argument("--file", default="queries.0")
    d.add_argument("--kafka", default=None, help="bootstrap servers, e.g. 10.0.0.5:9092,10.0.0.6:9092")
    d.add_argument("--topic", action="append", default=None, help="topic(s) to consume (repeatable)")
    d.add_argument("--group", default="daignosis", help="consumer group id")
    d.add_argument("--host", default="127.0.0.1")
    d.add_argument("--port", type=int, default=8080)
    d.add_argument("--batch", type=int, default=512)
    d.add_argument("--cache", default=".qvac-cache")
    d.add_argument("--var", default="var")
    d.add_argument("--clickhouse", default="http://127.0.0.1:8123")
    d.add_argument("--no-qvac", action="store_true")
    d.add_argument("--no-airgap", action="store_true")
    d.set_defaults(func=cmd_demo)

    pf = sub.add_parser("prefetch")
    pf.add_argument("--cache", default=".qvac-cache")
    pf.set_defaults(func=cmd_prefetch)

    pa = sub.add_parser("prove-airgap")
    pa.set_defaults(func=cmd_airgap)

    args = p.parse_args(argv)
    return args.func(args)
