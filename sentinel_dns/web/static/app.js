const chambersEl = document.getElementById("chambers");
const flowEl = document.getElementById("flow");
const flowMeta = document.getElementById("flow-meta");
const incidentEl = document.getElementById("incident");
const incidentEmpty = document.getElementById("incident-empty");
const wazuhEl = document.getElementById("wazuh");
const gate = document.getElementById("gate");

function fmt(n) {
  return new Intl.NumberFormat("es-PA").format(n);
}

function fillChamber(row) {
  const score = row.qoe_score ?? 0;
  const el = document.createElement("div");
  el.className = "chamber" + (row.qoe_status === "critical" ? " critical" : "");
  el.style.setProperty("--fill", `${Math.max(8, Math.min(100, score))}%`);
  const sla =
    row.qoe_status === "ok"
      ? ""
      : `${fmt(row.affected_queries || 0)} consultas en ${Math.round(row.degraded_seconds || 0)} s`;
  el.innerHTML = `
    <strong>${row.site}</strong>
    <div>${row.customer}</div>
    <p class="score">${Math.round(score)}</p>
    <div class="cause">${row.qoe_status} · ${row.root_cause || "—"}</div>
    <div class="cause">${Math.round(row.avg_dns_latency || 0)} ms · NX ${(row.nxdomain_rate * 100 || 0).toFixed(1)}%</div>
    <div class="cause">${sla}</div>
  `;
  return el;
}

function render(s) {
  document.getElementById("seen").textContent = fmt(s.processed || 0);
  document.getElementById("cloud").textContent = fmt(s.sovereignty.cloud_ai_calls || 0);
  document.getElementById("egress").textContent = fmt(s.sovereignty.external_data_transmitted_bytes || 0);
  const sealed = (s.sovereignty.external_data_transmitted_bytes || 0) === 0 && (s.sovereignty.cloud_ai_calls || 0) === 0;
  gate.dataset.sealed = sealed ? "true" : "false";
  document.getElementById("seal-state").textContent = sealed ? "cerrada" : "abierta — fugas";
  flowMeta.textContent = `${s.qps} q/s · origen ${s.source} · QVAC ${s.qvac.ready ? "listo" : (s.qvac.error || "cargando")}`;

  chambersEl.replaceChildren();
  const sites = (s.qoe || []).slice().sort((a, b) => a.site.localeCompare(b.site));
  if (!sites.length) {
    const ph = document.createElement("div");
    ph.className = "chamber";
    ph.textContent = "Aún no hay ventana de 5 s";
    chambersEl.appendChild(ph);
  } else {
    sites.forEach((row) => chambersEl.appendChild(fillChamber(row)));
  }

  flowEl.replaceChildren();
  (s.recent || []).slice(0, 18).forEach((ev) => {
    const li = document.createElement("li");
    if (ev.injected) li.className = "inj";
    li.innerHTML = `<span>${ev.site || ""}</span><span>${ev.qname}</span><span>${ev.qtype} ${ev.rcode} ${ev.latency_ms}ms</span>`;
    flowEl.appendChild(li);
  });

  const inc = (s.incidents || [])[0];
  if (!inc) {
    incidentEl.hidden = true;
    incidentEmpty.hidden = false;
  } else {
    incidentEmpty.hidden = true;
    incidentEl.hidden = false;
    document.getElementById("risk").textContent = inc.risk_score;
    document.getElementById("inc-title").textContent = `${inc.severity} · ${inc.kind} · confianza ${inc.confidence || "pendiente"}`;
    document.getElementById("inc-domain").textContent = inc.domain;
    const ul = document.getElementById("inc-signals");
    ul.replaceChildren();
    (inc.signals || []).forEach((sig) => {
      const li = document.createElement("li");
      li.textContent = sig;
      ul.appendChild(li);
    });
    document.getElementById("inc-explain").textContent = inc.explanation || "";
    document.getElementById("inc-action").textContent = inc.recommended_action || "";
    document.getElementById("inc-siem").textContent = inc.wazuh_sent
      ? `Webhook Wazuh entregado · QVAC local ${inc.qvac_used ? "sí" : "no"}`
      : "";
  }

  const alert = (s.alerts || [])[0];
  wazuhEl.textContent = alert ? JSON.stringify(alert, null, 2) : "sin alertas todavía";
}

async function tick() {
  try {
    const r = await fetch("/api/state");
    render(await r.json());
  } catch (err) {
    flowMeta.textContent = "consola sin contacto con el agente local";
  }
}

tick();
setInterval(tick, 500);
