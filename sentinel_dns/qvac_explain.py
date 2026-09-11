from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from queue import Empty, Queue

from sentinel_dns.models import Incident

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def template_explain(inc: Incident) -> tuple[str, str]:
    why = "; ".join(inc.signals) if inc.signals else inc.kind
    if inc.kind == "possible_c2_beaconing":
        expl = (
            f"Possible C2 beaconing. {why}. "
            f"{len(inc.affected_hosts)} internal hosts contacted {inc.domain}."
        )
        rec = "Investigate the affected endpoints and validate whether the domain is expected."
    elif inc.kind == "dns_tunneling":
        expl = f"Possible DNS tunneling toward {inc.domain}. {why}."
        rec = "Inspect TXT/label length on this apex and isolate the querying hosts."
    elif inc.kind == "typosquatting":
        expl = f"Possible typosquat of a protected brand: {inc.domain}. {why}."
        rec = "Block the domain at DNS and check whether users were directed there."
    elif inc.kind == "dga":
        expl = f"Domain looks algorithmically generated: {inc.domain}. {why}."
        rec = "Hunt the querying hosts for malware and sinkhole the domain if unused."
    else:
        expl = f"Suspicious DNS activity on {inc.domain}. {why}."
        rec = "Review the hosts and confirm business justification."
    return expl, rec


def qoe_template(snap: dict) -> str:
    site = snap["site"]
    cause = snap["root_cause"]
    if cause == "latency":
        detail = (
            f"Resolver latency is {snap['avg_dns_latency']} ms "
            f"(baseline {snap['baseline_latency']} ms). NXDOMAIN remains near normal."
        )
        likely = "Resolver or upstream network congestion."
    elif cause == "nxdomain":
        detail = f"NXDOMAIN rate is {snap['nxdomain_rate'] * 100:.1f}%."
        likely = "Application misconfig or a local DGA/NXDOMAIN burst."
    elif cause == "timeout":
        detail = f"Timeout/SERVFAIL rate is {snap['timeout_rate'] * 100:.1f}%."
        likely = "Resolver saturation or packet loss to upstream."
    else:
        detail = f"Query rate {snap['qps']} qps approaching site capacity."
        likely = "Client burst or insufficient resolver capacity."
    return (
        f"{site} DNS degradation. QoE {snap['qoe_score']}/100 ({snap['qoe_status']}). "
        f"Main contributor: {cause}. {detail} Likely cause: {likely}"
    )


class Explainer:
    def __init__(self, cache_dir: Path, enabled: bool = True) -> None:
        self.cache_dir = cache_dir
        self.enabled = enabled
        self.ready = False
        self.error: str | None = None
        self._q: Queue[Incident | dict | None] = Queue(maxsize=8)
        self._thread: threading.Thread | None = None
        self._on_incident = lambda inc: None
        self._on_qoe = lambda snap: None

    def start(self, on_incident, on_qoe) -> None:
        self._on_incident = on_incident
        self._on_qoe = on_qoe
        if not self.enabled:
            self.error = "QVAC disabled by flag"
            return
        self._thread = threading.Thread(target=self._run, name="qvac", daemon=True)
        self._thread.start()

    def submit_incident(self, inc: Incident) -> None:
        try:
            self._q.put_nowait(inc)
        except Exception:
            expl, rec = template_explain(inc)
            inc.explanation = expl
            inc.recommended_action = rec
            inc.qvac_used = False
            self._on_incident(inc)

    def submit_qoe(self, snap: dict) -> None:
        if snap.get("qoe_status") == "ok":
            snap["narrative"] = qoe_template(snap)
            self._on_qoe(snap)
            return
        try:
            self._q.put_nowait(snap)
        except Exception:
            snap["narrative"] = qoe_template(snap)
            snap["qvac_used"] = False
            self._on_qoe(snap)

    def stop(self) -> None:
        try:
            self._q.put_nowait(None)
        except Exception:
            pass

    def _run(self) -> None:
        try:
            import asyncio

            asyncio.run(self._amain())
        except Exception as exc:
            self.error = str(exc)
            self.ready = False
            self._drain_templates()

    def _drain_templates(self) -> None:
        while True:
            try:
                item = self._q.get(timeout=0.2)
            except Empty:
                if self._thread is None:
                    return
                continue
            if item is None:
                return
            if isinstance(item, Incident):
                expl, rec = template_explain(item)
                item.explanation = expl
                item.recommended_action = rec
                item.qvac_used = False
                self._on_incident(item)
            else:
                item["narrative"] = qoe_template(item)
                item["qvac_used"] = False
                self._on_qoe(item)

    async def _amain(self) -> None:
        from tetherto.qvac_sdk import Client, completion, load_model, unload_model
        from tetherto.qvac_sdk.models import QWEN3_600M_INST_Q4

        import os
        sdk_dir = os.environ.get("QVAC_SDK_DIR")
        if not sdk_dir:
            candidate = Path(os.environ.get("APPDATA", "")) / "npm" / "node_modules" / "@qvac" / "sdk"
            if (candidate / "dist" / "src" / "worker" / "index.js").exists():
                sdk_dir = str(candidate)

        cache = str(self.cache_dir.resolve())
        kwargs: dict = {"config": {"cacheDirectory": cache}}
        if sdk_dir:
            kwargs["sdk_dir"] = sdk_dir
        async with Client(**kwargs) as client:
            t = client.transport
            model_id = await load_model(
                t,
                model_src=QWEN3_600M_INST_Q4,
                model_config={"ctx_size": 2048},
            )
            self.ready = True
            try:
                while True:
                    item = await _queue_get(self._q)
                    if item is None:
                        break
                    if isinstance(item, Incident):
                        await self._explain_incident(t, model_id, item)
                    else:
                        await self._explain_qoe(t, model_id, item)
            finally:
                await unload_model(t, model_id)

    async def _explain_incident(self, t, model_id, inc: Incident) -> None:
        payload = {
            "domain": inc.domain,
            "risk_score": inc.risk_score,
            "incident_type": inc.kind,
            "signals": inc.signals,
            "affected_hosts": len(inc.affected_hosts),
            "site": inc.site,
        }
        prompt = (
            "You are a SOC assistant. Explain ONLY this evidence. Do not invent detections. "
            "Reply with JSON only: "
            '{"severity":"critical|high|medium","incident_type":"string",'
            '"explanation":"string","recommended_action":"string"}\n'
            + json.dumps(payload)
        )
        parsed = await self._complete_json(t, model_id, prompt)
        expl, rec = template_explain(inc)
        if parsed:
            inc.explanation = str(parsed.get("explanation") or expl)
            inc.recommended_action = str(parsed.get("recommended_action") or rec)
            inc.qvac_used = True
        else:
            inc.explanation = expl
            inc.recommended_action = rec
            inc.qvac_used = False
        self._on_incident(inc)

    async def _explain_qoe(self, t, model_id, snap: dict) -> None:
        prompt = (
            "You are a network operator assistant. Explain DNS QoE using only this evidence. "
            "JSON only: {\"explanation\":\"string\",\"likely_cause\":\"string\"}\n"
            + json.dumps({k: snap[k] for k in snap if k != "components"})
        )
        parsed = await self._complete_json(t, model_id, prompt)
        if parsed:
            snap["narrative"] = (
                f"{parsed.get('explanation', '')} Likely cause: {parsed.get('likely_cause', '')}"
            ).strip()
            snap["qvac_used"] = True
        else:
            snap["narrative"] = qoe_template(snap)
            snap["qvac_used"] = False
        self._on_qoe(snap)

    async def _complete_json(self, t, model_id, prompt: str) -> dict | None:
        from tetherto.qvac_sdk import completion

        try:
            run = completion(
                t,
                model_id=model_id,
                history=[{"role": "user", "content": prompt}],
            )
            final = await run.final
            text = getattr(final, "content_text", None) or getattr(final, "contentText", "") or ""
            m = _JSON_RE.search(text)
            if not m:
                return None
            return json.loads(m.group(0))
        except Exception:
            return None


async def _queue_get(q: Queue):
    import asyncio

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, q.get)
