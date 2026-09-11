# Sentinel-DNS

Agente local de inteligencia DNS para el reto Ovnicom / QVAC Track 04.

Detecta DGA, typosquatting, tunneling y beaconing sobre el stream, prioriza con un risk score, explica el incidente con **QVAC en el dispositivo**, calcula QoE por sitio con baselines, y prueba que **cero bytes de telemetría salen** de `127.0.0.1`.

> Detectar → correlacionar → priorizar → explicar → diagnosticar → mostrar impacto. Sin nube de inferencia.

## Base preexistente (obligatorio declararla)

| Qué | Origen | Uso |
|-----|--------|-----|
| Logs BIND9 `queries.*` | Dataset sintético del reto Ovnicom (`LogsDNSQueries`) | Replay del stream. **No son datos de clientes reales.** |
| Overlay latencia / RCODE / customer-site | Generado por este repo (`sentinel_dns/overlay.py`, `config/sites.json`) | Los query logs de BIND **no traen** latencia ni NXDOMAIN. El QoE usa este overlay, declarado aquí. |
| Dominio de campaña `xjs83kavqpwm.xyz` | Inyectado en demo | Escenario de DGA + beacon |
| QVAC SDK y `QWEN3_600M_INST_Q4` | Tether / QVAC | Única inferencia. Local, 1 llamada por incidente |

Omitir esta tabla descalifica según las reglas del hackathon.

## Qué no hace este repo

- No llama APIs de inferencia en la nube (descalificación directa).
- No corre Kafka ni Wazuh manager (el contrato SIEM es JSON tipo `alerts.json` a un webhook local).
- No entrena sklearn. Nivel 1 = heurística en stdlib.
- No bloquea DNS (un falso positivo arruinaría el demo).

## Requisitos

- Python ≥ 3.10
- Node.js ≥ 22.17 (worker QVAC)
- Opcional: Docker Desktop para ClickHouse + Grafana en localhost

## Arranque (todo en este host)

```bash
cd sentinel-dns
python -m sentinel_dns prove-airgap
python -m sentinel_dns demo --data "../LogsDNSQueries 2/LogsDNSQueries"
```

Consola: [http://127.0.0.1:8080](http://127.0.0.1:8080)

Sin el zip del reto, el demo genera tráfico benigno sintético y **sí** inyecta la campaña:

```bash
python -m sentinel_dns demo --no-qvac
```

`--no-qvac` usa plantillas de explicación. El camino del jurado es QVAC local:

```bash
pip install -r requirements-qvac.txt
python -m tetherto.qvac_sdk install-worker
python -m sentinel_dns prefetch
python -m sentinel_dns demo
```

`prefetch` descarga el modelo **antes** del video. En el demo, `load_model` lee el cache en disco. `SENTINEL` instala un guard de sockets: cualquier destino que no sea loopback lanza `PermissionError` y sube `egress_bytes`.

## Arquitectura

```
BIND queries.* (o sintético)
        → micro-batch 512, cola acotada, ~420 q/s
        → overlay IP→sitio + latencia/RCODE
        → inyección de escenario (45 s beacon, 90 s degradación Panama-East)
        → heurística (entropy, labels, inter-arrival deque)
              ├ risk ≥ 45 → QVAC JSON → alerta Wazuh local
              └ QoE 5 s / sitio → var/*.jsonl (y ClickHouse si :8123 vive)
```

QVAC **no** ve cada query. Recibe evidencia ya calculada.

## Demo de 5 minutos

| t | Qué mostrar |
|---|-------------|
| 0:00 | Consola en `127.0.0.1:8080`. Esclusa **cerrada**. Cloud AI 0. Bytes 0. |
| 0:45 | Cinco hosts de Panama-East preguntan `xjs83kavqpwm.xyz` con cadencia ~6 s |
| ~1:15 | Risk alto, explicación QVAC, JSON Wazuh en pantalla |
| 1:30 | Panama-East sube a ~96 ms. QoE cae. Causa = latencia (NXDOMAIN sigue normal) |
| 3:30 | Impacto: consultas afectadas × segundos. Panel de soberanía sigue en 0 |
| 4:30 | `python -m sentinel_dns prove-airgap` → PASS |

## ClickHouse / Grafana (opcional)

Este entorno de desarrollo **no tiene Docker**. Si el jurado sí:

```bash
docker compose up -d
```

Bind: `127.0.0.1:8123` y `127.0.0.1:3000`. Sin Docker, las métricas quedan en `var/qoe.jsonl` y `var/incidents.jsonl` y la consola local las muestra igual.

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Rúbrica

| Eje | Dónde está |
|-----|------------|
| Technical | Stream + micro-batch + heurística + QVAC on-device + JSON Wazuh |
| Innovation | Risk + explicación + root-cause por sitio + impacto SLA |
| Impact | Operador de red (QoE interpretable) y SOC (priorización) |
| Design | Consola “esclusa del canal”: el dato no sale al mar |
| Completion | Este README, demo autónomo, overlay declarado |

## Licencia

Entrega de hackathon. No se exige licencia abierta.
