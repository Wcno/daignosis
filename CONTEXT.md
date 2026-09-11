# Sentinel DNS

Sentinel DNS turns DNS telemetry into prioritized, sovereign security intelligence for network operators.

## Language

**Finding**:
A detector-produced observation about DNS behavior that may be suspicious but is not yet an operator-level conclusion.
_Avoid_: Alert, anomaly, incident

**Security Incident**:
A QVAC-correlated, operator-actionable conclusion that groups related findings by affected site, hosts, indicators, and time window.
_Avoid_: Finding, raw alert, event

**Coordinated Malware Campaign**:
A security incident in which multiple hosts exhibit related malicious DNS behavior toward shared infrastructure within a defined period.
_Avoid_: Isolated suspicious query

**Telemetry Stream**:
The existing Kafka flow of normalized DNS events that Sentinel consumes independently without changing its producer or other consumers.
_Avoid_: Replay file, Sentinel pipeline

**QoE Score**:
An interpretable per-site and customer-zone measure of DNS resolution experience based on latency, NXDOMAIN rate, and saturation signals.
_Avoid_: Security risk score, health status

**Baseline**:
The recent normal DNS behavior for one site and customer zone against which its QoE measurements are evaluated.
_Avoid_: Fixed global threshold, capacity limit

**Wazuh-compatible Alert**:
A locally delivered JSON security incident payload containing fields that a Wazuh rule or decoder can process.
_Avoid_: Dashboard-only alert, Wazuh Manager instance

**Correlation Window**:
A 60-second site-scoped period in which QVAC may combine findings that share an indicator and affect at least three hosts into a Security Incident.
_Avoid_: Per-query classification, unbounded history
