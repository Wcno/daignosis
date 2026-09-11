from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
from pathlib import Path

from sentinel_dns.clickhouse import MetricSink
from sentinel_dns.egress import GUARD
from sentinel_dns.pipeline import Pipeline, open_source
from sentinel_dns.producer import DemoProducer
from sentinel_dns.qvac_explain import Explainer
from sentinel_dns.qvac_runtime import prepare_worker_runtime
from sentinel_dns.server import serve
from sentinel_dns.state import AppState
from sentinel_dns.stream import CONSUMER_GROUP, TOPIC, KafkaEventSource, KafkaPublisher
from sentinel_dns.webhook import WazuhWebhook


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


def _run_agent(args: argparse.Namespace, source, source_name: str, inject_scenario: bool) -> int:
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    var = Path(args.var)
    var.mkdir(parents=True, exist_ok=True)
    if not args.no_airgap:
        GUARD.install()
    state = AppState()
    state.source = source_name
    explainer = Explainer(cache_dir=cache, enabled=not args.no_qvac)
    sink = MetricSink(url=args.clickhouse, var_dir=var)
    webhook_url = args.wazuh_webhook or f"http://{args.host}:{args.port}/ingest/wazuh"
    webhook = WazuhWebhook(webhook_url)
    pipe = Pipeline(
        state=state,
        explainer=explainer,
        sink=sink,
        webhook=webhook,
        batch_size=args.batch,
        inject_scenario=inject_scenario,
    )
    httpd = serve(state, args.host, args.port)
    t_http = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    t_http.start()
    print(f"Sentinel-DNS http://{args.host}:{args.port} source={state.source}", flush=True)
    try:
        pipe.run(source)
    finally:
        pipe.stop = True
        httpd.shutdown()
        httpd.server_close()
        GUARD.restore()
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    data = Path(args.data) if args.data else _default_data()
    source = open_source(data if data and data.exists() else None, args.file)
    source_name = str(data) if data and data.exists() else "synthetic-benign+inject"
    return _run_agent(args, source, source_name, inject_scenario=True)


def cmd_consume(args: argparse.Namespace) -> int:
    source = KafkaEventSource(args.bootstrap, topic=args.topic, group_id=args.group)
    return _run_agent(args, source, f"kafka:{args.topic} group={args.group}", inject_scenario=False)


def cmd_produce(args: argparse.Namespace) -> int:
    data = Path(args.data) if args.data else _default_data()
    source = open_source(data if data and data.exists() else None, args.file)
    publisher = KafkaPublisher(args.bootstrap, topic=args.topic)
    print(f"Sentinel DNS producer topic={args.topic}", flush=True)
    DemoProducer(publisher, source, qps=args.qps).run()
    return 0


def cmd_prefetch(args: argparse.Namespace) -> int:
    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)

    async def go() -> None:
        prepare_worker_runtime()
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


def _add_agent_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--batch", type=int, default=512)
    parser.add_argument("--cache", default=".qvac-cache")
    parser.add_argument("--var", default="var")
    parser.add_argument("--clickhouse", default="http://127.0.0.1:8123")
    parser.add_argument("--wazuh-webhook", default=None)
    parser.add_argument("--no-qvac", action="store_true")
    parser.add_argument("--no-airgap", action="store_true")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-dns")
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo")
    demo.add_argument("--data", default=None)
    demo.add_argument("--file", default="queries.0")
    _add_agent_args(demo)
    demo.set_defaults(func=cmd_demo)

    produce = sub.add_parser("produce")
    produce.add_argument("--data", default=None)
    produce.add_argument("--file", default="queries.0")
    produce.add_argument("--bootstrap", default="127.0.0.1:9092")
    produce.add_argument("--topic", default=TOPIC)
    produce.add_argument("--qps", type=float, default=420.0)
    produce.set_defaults(func=cmd_produce)

    consume = sub.add_parser("consume")
    consume.add_argument("--bootstrap", default="127.0.0.1:9092")
    consume.add_argument("--topic", default=TOPIC)
    consume.add_argument("--group", default=CONSUMER_GROUP)
    _add_agent_args(consume)
    consume.set_defaults(func=cmd_consume)

    prefetch = sub.add_parser("prefetch")
    prefetch.add_argument("--cache", default=".qvac-cache")
    prefetch.set_defaults(func=cmd_prefetch)

    airgap = sub.add_parser("prove-airgap")
    airgap.set_defaults(func=cmd_airgap)

    args = parser.parse_args(argv)
    return args.func(args)
