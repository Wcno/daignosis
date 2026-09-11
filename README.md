# dAIgnosis

![Python](https://img.shields.io/badge/Python-%E2%89%A53.10-3776AB?logo=python&logoColor=white)
![Licencia](https://img.shields.io/badge/Licencia-MIT-green?style=flat)
![Lenguaje principal](https://img.shields.io/badge/Lenguaje%20principal-Python-3776AB?logo=python&logoColor=white)

## 1. Descripción

**Una capa de inteligencia DNS soberana.** dAIgnosis usa **QVAC en local** para convertir telemetría DNS en tiempo real en incidentes correlacionados, explicables y diagnóstico proactivo, **100% dentro de la infraestructura del cliente**.

Los ataques basados en DNS —DGA, typosquatting, tunneling y beaconing— generan miles de alertas sin contexto. dAIgnosis conecta el stream que el operador ya tiene, prioriza lo importante y transforma eventos DNS en decisiones accionables para SOC y NOC.

![Consola dAIgnosis](./docs/qoe-dashboard.png)

La consola concentra el stream Kafka, la correlación de campañas con QVAC local, la QoE por sitio, la alerta Wazuh y la prueba de cero egreso.

![Flujo DNS e incidente prioritario](./docs/stream-and-incident.png)

![Campañas correlacionadas y alerta Wazuh](./docs/campaigns-and-wazuh.png)

## 2. Rol de QVAC

QVAC es la capa de inteligencia del producto, no un generador de texto añadido al final del pipeline.

- Recibe las anomalías estructuradas de los últimos 120 segundos: dominios, sitios, hosts, señales y cadencias.
- Correlaciona múltiples hallazgos para distinguir una campaña coordinada de eventos aislados.
- Explica por qué los eventos pertenecen al mismo incidente y recomienda la acción operativa.
- Diagnostica degradación de QoE usando evidencia de latencia, NXDOMAIN, timeouts, saturación y baseline por sitio.
- Ejecuta toda la inferencia localmente; ninguna consulta DNS ni dato derivado se envía a una API de IA en la nube.

```text
BIND queries.* | Kafka (dns-queries, texto/JSON) | sintético
        → detección de anomalías
        → ventana local de correlación QVAC
        → campaña explicable y priorizada
        → Wazuh / QoE / ClickHouse / Grafana
```

QVAC no ve cada query cruda: recibe evidencia calculada y toma la decisión difícil de correlación y narrativa. Así convierte miles de eventos en pocos incidentes comprensibles.

## 3. Valor generado

### Para el SOC

- Menos ruido: DGA, typosquatting, tunneling y beaconing se agrupan por riesgo, dominio, sitio y host.
- Un veredicto de campaña en lugar de una lista de timestamps.
- Alertas Wazuh con severidad, señales, hosts afectados, explicación y acción recomendada.

### Para el NOC

- QoE 0–100 por sitio y zona.
- Baseline adaptativo EWMA para detectar desviaciones del comportamiento normal.
- Causa raíz interpretable: latencia, NXDOMAIN, timeout o saturación.
- Impacto operativo: consultas afectadas, segundos degradados y estado SLA.

### Para operadores y clientes regulados

- Consume logs BIND9 o topics Kafka sin modificar el pipeline de producción.
- Funciona on-prem y mantiene la inferencia dentro del datacenter.
- Comprueba el aislamiento con un guard de sockets y la métrica `egress_bytes`.
- Se integra con la infraestructura existente: Kafka, Wazuh, ClickHouse y Grafana.

### Impacto medible

| Métrica | Operación tradicional | Con dAIgnosis |
|---------|-----------------------|---------------|
| Alertas revisadas por el SOC | miles por día | incidentes priorizados y campañas correlacionadas |
| Triage por incidente | varias herramientas | explicación y acción recomendada en una vista |
| Diagnóstico de degradación | después del ticket | causa raíz por sitio desde el stream |
| Datos fuera de la red | telemetría hacia la nube | 0 bytes de inferencia externa |

### Modelo de negocio

| Oferta | Cliente | Valor capturado |
|--------|---------|-----------------|
| Licencia on-prem por resolver/sitio | Operadores, ISPs, grandes empresas | Despliegue sobre infraestructura existente |
| Seguridad DNS como servicio | ISP y clientes corporativos | Nuevo ingreso recurrente con coste marginal bajo |
| Correlación y explicación con QVAC | SOC | No solo detecta: explica qué pasó y qué hacer |
| Diagnóstico de QoE por sitio | NOC y cliente | Detecta degradación antes de los tickets |
| Cumplimiento y soberanía verificable | Finanzas, salud y gobierno | IA local y cero egreso demostrable |

## 4. Setup

### Quickstart

```bash
python -m daignosis smoke
```

Consola local: `http://127.0.0.1:8080`. Sal con `Ctrl+C`.

Sin SDK QVAC o sin abrir el navegador:

```bash
python -m daignosis smoke --no-qvac --no-open
```

### Ejecución con datos sintéticos o BIND

```bash
cd daignosis
python -m daignosis prove-airgap
python -m daignosis demo --data "../LogsDNSQueries 2/LogsDNSQueries"
```

Sin dataset, genera tráfico benigno e inyecta una campaña:

```bash
python -m daignosis demo --no-qvac
```

### Kafka en tiempo real

```bash
pip install -r requirements-kafka.txt
python -m daignosis demo \
  --kafka 10.0.0.5:9092,10.0.0.6:9092 \
  --topic dns-queries \
  --group daignosis
```

El guard anti-egreso autoriza solo los brokers configurados como fuente de ingesta.

### Wazuh local

```bash
python -m daignosis demo \
  --kafka 127.0.0.1:9092 \
  --wazuh-webhook http://127.0.0.1:55000/daignosis
```

El endpoint Wazuh debe ser local (`127.0.0.1`, `localhost` o `::1`).

### Activa QVAC local

```bash
pip install -r requirements-qvac.txt
python -m tetherto.qvac_sdk install-worker
python -m daignosis prefetch
python -m daignosis demo
```

### Stack opcional

- Python ≥ 3.10.
- Node.js ≥ 22.17 para el worker QVAC.
- Kafka mediante `confluent-kafka`.
- ClickHouse y Grafana con Docker:

```bash
docker compose up -d
```

Sin Docker, las métricas quedan en `var/qoe.jsonl` y `var/incidents.jsonl`.

### Pruebas

```bash
python -m unittest discover -s tests -v
```

### Licencia

Este proyecto está disponible bajo la [licencia MIT](./LICENSE).
