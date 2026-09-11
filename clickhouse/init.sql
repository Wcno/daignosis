CREATE TABLE IF NOT EXISTS qoe_metrics (
  ts DateTime64(3),
  customer LowCardinality(String),
  site LowCardinality(String),
  zone LowCardinality(String),
  avg_dns_latency Float64,
  nxdomain_rate Float64,
  timeout_rate Float64,
  qps Float64,
  qoe_score Float64,
  qoe_status LowCardinality(String),
  root_cause String,
  affected_queries UInt64,
  degraded_seconds Float64
) ENGINE = MergeTree ORDER BY (site, ts);

CREATE TABLE IF NOT EXISTS dns_incidents (
  ts DateTime64(3),
  domain String,
  kind LowCardinality(String),
  risk_score UInt8,
  severity LowCardinality(String),
  site String,
  customer String,
  explanation String
) ENGINE = MergeTree ORDER BY (ts, domain);
