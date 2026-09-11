# Sentinel-DNS

Agente local de inteligencia DNS para el reto Ovnicom / QVAC Track 04.

Sentinel consume telemetría DNS normalizada como consumidor adicional de Kafka.

Los detectores producen Findings deterministas.

QVAC local correlaciona Findings de una ventana de 60 segundos en un Security Incident accionable.

El agente entrega el incidente por webhook local en JSON compatible con Wazuh y mantiene el QoE Score por sitio y zona de cliente.

> Kafka → Findings → QVAC local → Security Incident → webhook Wazuh local.
>
> Ninguna telemetría DNS ni dato derivado sale de la infraestructura.

## Base preexistente

| Qué | Origen | Uso |
|---|---|---|
| Logs BIND9 `queries.*` | Dataset sintético del reto Ovnicom (`LogsDNSQueries`) | Fuente opcional del productor de demostración. No son datos de clientes reales. |
| Overlay de latencia, RCODE y customer-site | Generado por este repositorio | Enriquece los eventos sintéticos antes de publicarlos a Kafka. |
| Dominio de campaña `xjs83kavqpwm.xyz` | Inyectado en la demostración | Escenario DGA y beaconing coordinado. |
| QVAC SDK y `QWEN3_600M_INST_Q4` | Tether / QVAC | Única inferencia para crear Security Incidents. Se ejecuta localmente. |

## Arquitectura

```text
Productor sintético dnstap-like
        ↓
Kafka topic dns.telemetry.v1
        ↓
Sentinel consumer group sentinel-dns
        ├─→ Detectores → Findings visibles
        ├─→ QVAC local → Security Incident
        │                 ↓
        │          webhook local Wazuh-compatible
        └─→ QoE Score → ClickHouse → Grafana
```

Sentinel no modifica al productor ni a otros consumidores del stream.

## Requisitos

- Python 3.10 o superior.
- Node.js 22 o superior.
- Docker Desktop o Docker Engine para Kafka, ClickHouse y Grafana.
- Vulkan o CPU local para QVAC.

## Arranque de demostración

Instale las dependencias antes de grabar el video.

```bash
uv venv
uv pip install --python .venv/bin/python -e . -r requirements-qvac.txt
.venv/bin/python -m tetherto.qvac_sdk install-worker
.venv/bin/python -m sentinel_dns prefetch
docker compose up -d kafka clickhouse grafana
```

`prefetch` descarga el modelo antes de la demostración.

El modelo usado por QVAC es específico de `QWEN3_600M_INST_Q4`.

Los archivos GGUF de otros tracks no son intercambiables con ese artefacto QVAC.

Abra primero el consumidor y espere el estado `QVAC listo` en la consola.

```bash
.venv/bin/python -m sentinel_dns consume --group sentinel-dns-demo-1
```

En una segunda terminal, inicie el productor.

```bash
.venv/bin/python -m sentinel_dns produce
```

Consola local: [http://127.0.0.1:8080](http://127.0.0.1:8080)

El productor emite tráfico benigno para el warm-up.

A los 45 segundos inyecta un spike NXDOMAIN y cinco hosts de Panama-East consultando el dominio DGA-like en cadencia de seis segundos.

El correlador exige dos tipos de Finding, tres hosts y un indicador compartido en 60 segundos.

QVAC convierte esa evidencia en un único Security Incident y Sentinel lo envía por POST a `http://127.0.0.1:8080/ingest/wazuh`.

A los 90 segundos, el productor introduce la degradación de latencia para mantener la demostración de QoE.

Use un grupo nuevo en cada repetición del video, por ejemplo `--group sentinel-dns-demo-2`.

## Prueba de soberanía

Durante el consumidor, el guard de egress permite exclusivamente `127.0.0.1`, `::1` y `localhost`.

Kafka, QVAC, ClickHouse, Grafana y el webhook Wazuh se usan con endpoints locales.

Ejecute además:

```bash
.venv/bin/python -m sentinel_dns prove-airgap
```

El resultado debe ser `PASS` para el intento de conexión a `1.1.1.1`.

## Comportamiento ante fallo de QVAC

Los detectores siguen exponiendo Findings cuando QVAC está indisponible.

Sentinel no crea Security Incidents ni envía alertas Wazuh mediante plantillas.

Así, QVAC es imprescindible para la conclusión que ve el operador.

## Pruebas

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Las pruebas cubren detectores, QoE, zero egress, contrato del evento Kafka, correlación de campaña, límite de fallo de QVAC y entrega de webhook local.

## Alcance intencional

No corre un Wazuh Manager completo.

El reto exige un formato que Wazuh pueda procesar y envío por webhook o API local, ambos demostrados por Sentinel.

No se bloquea DNS y no se envía telemetría a inferencia cloud.
