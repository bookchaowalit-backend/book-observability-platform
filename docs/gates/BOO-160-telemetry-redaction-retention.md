# BOO-160: redacted telemetry schema and retention

Status: **evidence and proposal only.** Nothing here records an owner decision,
connects a dashboard, changes a retention setting or moves a runtime.

## Next gate (verbatim)

> Define redacted telemetry schema and retention before connecting existing dashboards.

## Contract sections this answers

Contract: `bookchaowalit/architecture-docs` @ `687d228`,
`systems/architecture/solo-empire-api-contract-v1.md` (marked *Retired
2026-10-11* and kept as the historical contract; it is still the named contract
for this gate).

| Section (anchor) | Lines | What it requires | Answered by |
|---|---|---|---|
| `#operational-limits-and-failure-behavior`, row *Observability* | 163 | Gap: "Add structured logs, latency metrics, centralized audit retention, and SLO evidence" | Schema `log` / `metric` / `trace` variants and the retention table below (SLO evidence is not covered) |
| `#authentication-classes` | 63-65 | Provider credentials must not be written to responses, logs, tasks or payload metadata | `x-forbidden.keys` (token, authorization, api_key, secret, provider…) and `value_patterns` (bearer, JWT, provider keys, private keys) |
| `#bookfinance-api-v1` | 104-107 | Only redacted access metadata (subject, scope, route, status, query-key names); raw bearer tokens and payload values never persisted | Closed objects with no free-text field; `route` is a template or route class; amounts and currency strings rejected |

## What this change adds

| File | Purpose |
|---|---|
| [`schema/telemetry/redacted-telemetry-event.v1.schema.json`](../../schema/telemetry/redacted-telemetry-event.v1.schema.json) | JSON Schema (2020-12) allow-list: one `log`, `metric`, `trace` or `health_snapshot` per document. Every object is `additionalProperties: false`; there is no free-text field. `x-forbidden` lists forbidden keys and value patterns. |
| [`scripts/telemetry_policy.py`](../../scripts/telemetry_policy.py) | Dependency-free validator for that schema plus the `x-forbidden` scan, and `redact_health_snapshot()` which maps the real `system_health.full_health()` payload onto the allow-list. |
| [`fixtures/gates/telemetry-redaction-retention.json`](../../fixtures/gates/telemetry-redaction-retention.json) | Machine-readable gate record: contract references, retention table, dashboard consumers, and the per-field source inventory with a disposition (keep / transform / drop) and `file:line` for each field. |
| `fixtures/telemetry/{valid,invalid,raw}/` | Synthetic events only. 8 valid, 20 invalid (each with the expected rejection reason), and one synthetic raw `system_health` payload. |
| [`tests/test_telemetry_policy.py`](../../tests/test_telemetry_policy.py) | Run by `bash scripts/check.sh` (unittest discover). |

## Current sources (inventory)

`infra/scripts/utils/system_health.py` and `infra/self-hosted-stack` no longer
exist at solo-empire `HEAD` (removed in `5f034945` and `9f44f602`, 2026-10-11).
The inventory reads the last revisions that contained them: `99ddc05c` for
`system_health.py`, `b606a119` for `infra/self-hosted-stack` and
`infra/api/telemetry.ts`.

### Health snapshot: `system_health.py` `full_health()` (99ddc05c:174-258)

| Source field | Line | Disposition | Target |
|---|---|---|---|
| `schema_version` | 177 | transform | `source_schema_version` (only `"1.0"` accepted) |
| `timestamp` (naive local time) | 178 | transform | `observed_at` (UTC, `Z`) |
| `revenue.unavailable` | 48 | transform | `sections.finance.available` |
| `revenue.received / pending / total / entries / reporting_currency / received_display / pending_display / by_currency` | 49-56 | **drop** | raw finance amounts and ledger detail |
| `goals.*`, `habits.*`, `tasks.*` counts | 70, 82, 91 | **drop** | personal productivity records; only `available` is kept |
| `cron.total / active / success / failed` | 110 | keep | `sections.cron.*` |
| `cron.pending` | 112 | transform | `sections.cron.pending_jobs` (`pending` is a forbidden finance key) |
| `cron.recent[].job_type / last_run / status` | 106 | keep (validated) | job types must match `^[a-z][a-z0-9_]{0,63}$`; timestamps to UTC |
| `cron.failed_jobs` | 107 | keep | `sections.cron.failed_jobs` |
| `cron.error`, `freshness.error`, `alerts.error` | 117, 135, 154 | **drop** | `str(e)` free text |
| `freshness.ok / stale / missing`, `alerts.critical / warnings / info` | 213, 234-236, 353-357 | keep | counts only; other summary keys dropped |
| `credentials.<x>.status` | 298 | keep | enum `configured / not_configured / error` |
| `credentials.<x>.message`, `credentials.<x>.provider` | 271, 285 | **drop** | free text; secret-provider name |
| `system_health`, `business_health`, `score` | 222, 242, 252 | transform | `grades.system / business / overall` |

### Traces: `infra/api/telemetry.ts` (b606a119)

| Source | Line | Disposition |
|---|---|---|
| resource `service.name`, `service.version` | 29-31 | keep |
| span attribute `http.method` | server.ts:524 | keep |
| span attribute `http.route` | server.ts:524 | transform: source sets `url.pathname` (a raw path); it has to become the route template (G2) |
| span status message = `error.message` | 70-73 | **drop** (G2) |
| `HttpInstrumentation` default attributes (`http.url`, `http.target`, `net.peer.ip`, `http.user_agent`…) | 34 | **drop** |

### Logs: `platform-api-gateway` `request.completed` (6e1fb34 `src/book_api_gateway/server.py:363-372`)

`event`, `method`, `route` (route class), `request_id`, `status`, `latency_ms`,
`subject_hash` are all kept and fit the `log` variant unchanged. PR #1 in this
repository (unmerged, branch `codex/shared-infrastructure-20261015`) would add
an access-log line from `src/platform_observability/middleware.py` with
`service`, `method`, `route`, `status`, `duration_seconds`, `correlation_id` and
`trace_id`. Each of those maps 1:1 onto the `log` variant
(`fixtures/telemetry/valid/log-access-middleware.json`). This branch is cut from
`main` and touches none of PR #1's files.

### Existing dashboards

| Consumer | Source | What it reads | Constraint on this gate |
|---|---|---|---|
| `bookchaowalit-ai/data-analytics-dashboard-web` @ `1f35f42` | `lib/analytics.ts:20-24`, README "CSV contract" | Browser-only CSV with `timestamp`, `segment`, `value`. Windows: 24H / 7D / 30D | Metric retention must be at least 30 days. If it is ever fed from this platform, `segment` must be a schema label value, never a person or customer. Today it reads no telemetry store. |
| Grafana provisioning (solo-empire @ `b606a119`) | `grafana/provisioning/dashboards/{service-overview,system-metrics,mlops-reference}.json` | `up`, `node_*`, `traefik_service_requests_total`, `ALERTS`, `solo_empire_mlops_*`. Labels: `mode, fstype, mountpoint, device, cpu, service, code, alertstate, alertname, job, model_name, model_version` | Every metric name and label is on the allow-list (tested). `instance` must be `service:port`; IP literals and `/home/*` mountpoints are rejected. |

## Retention policy (proposed)

| Signal | `retention_class` | Store | Current (source) | Proposed | Purge after expiry | Backups |
|---|---|---|---|---|---|---|
| metric | `metric-30d` | Prometheus TSDB | 30d (`docker-compose.yml:361`) | **30 days** (covers the widest dashboard window) | ≤ 24 h | excluded |
| log | `log-14d` | Loki | **Unbounded.** No compactor `retention_enabled` / `retention_period`; only `reject_old_samples_max_age: 168h` on ingest (`loki/loki.yml:33-38`) | **14 days** | ≤ 24 h | excluded |
| trace | `trace-7d` | Tempo | Not configured, so the default `block_retention` of 336 h applies (`tempo/tempo.yml:17-23`). Storage lives under `/var/tempo`, but the volume is mounted at `/tmp/tempo` (`docker-compose.yml:1777`), so data is lost when the container is recreated. | **7 days** | ≤ 24 h | excluded |
| health_snapshot | `health-90d` | file/object store | **Unbounded.** `--save` writes `health-DATE.json` with raw revenue amounts and never prunes it (`system_health.py:381-387`) | **90 days**, redacted snapshots only | ≤ 24 h | excluded |

Each event carries its `retention_class`. The schema fixes it per signal, so a
log cannot claim metric retention.

## Gaps

| ID | Gap | Evidence |
|---|---|---|
| G1 | No redaction code exists on `main` of this repository. The redactor here covers health snapshots only. Logs and traces depend on producers emitting allow-listed fields. | `git ls-tree origin/main` |
| G2 | `telemetry.ts` sets `http.route` to the raw `url.pathname` and copies `error.message` into the span status. `HttpInstrumentation` adds the full URL, peer IP and user agent. The schema rejects all of these, but nothing in the source strips them yet. | telemetry.ts:34, 70-73; server.ts:524 |
| G3 | `system_health.py` returns `str(e)` for cron, freshness and alert failures, and `--save` persists raw revenue amounts. | :117, :135, :154, :381-387 |
| G4 | `system_health.py` timestamps are naive local time. The redactor assumes UTC unless told otherwise. | :178 |
| G5 | The gateway accepts a client-supplied `X-Request-ID` matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, which admits IP literals. Only the value scan catches this (proved against the real gateway when `PLATFORM_API_GATEWAY_SRC` is set). | gateway server.py:26, 134-138 |
| G6 | `subject_hash` is an unkeyed `sha256(token)[:16]`. It is a stable pseudonym, linkable across events and across 14 days of logs. A keyed HMAC with rotation is not designed here. | gateway server.py:229 |
| G7 | Loki has no retention and Tempo's volume path does not match its storage path. Neither is changed here. | see table |
| G8 | Alertmanager notification history, Grafana annotations and the audit log are not covered. `audit_log` retention ("centralized audit retention", contract line 163) still needs its own decision. | contract:163 |
| G9 | The two source-drift checks (`SYSTEM_HEALTH_SOURCE`, `PLATFORM_API_GATEWAY_SRC`) need local checkouts and are skipped in CI. In CI the inventory is checked against the synthetic raw fixture only. | tests |

## Verification

```bash
bash scripts/check.sh
# optional, with local checkouts:
SYSTEM_HEALTH_SOURCE=/path/system_health.py \
PLATFORM_API_GATEWAY_SRC=/path/platform-api-gateway/src \
  python3 -m unittest -v tests.test_telemetry_policy
```

The tests fail if:

- a valid fixture breaks the schema, or an invalid fixture passes or fails for a different reason;
- any forbidden key (top level, metric label, span attribute) or forbidden value pattern is accepted;
- an allowed field is itself a forbidden key, or any object is left open;
- `redact_health_snapshot()` output stops validating, changes from the committed fixture, or leaks a dropped value;
- a raw `system_health` field has no disposition, or (with `SYSTEM_HEALTH_SOURCE`) the real producer emits a key the inventory does not cover;
- a retention row is missing or mismatched for a signal, or metric retention falls below the widest dashboard window;
- a Grafana metric or label used today is not on the allow-list;
- (with `PLATFORM_API_GATEWAY_SRC`) a real gateway event is not schema-valid, or its field set drifts from the inventory.

## Owner decision — PROPOSED, NOT ACCEPTED

The owner (`bookchaowalit-backend`, observability platform) is asked to accept
or amend:

1. Telemetry reaching this platform must validate against
   `observability.telemetry.v1` (this schema). The schema is an allow-list,
   has no free-text field, and the `x-forbidden` scan stays on even if an
   object is opened later.
2. Retention: metrics 30 days, logs 14 days, traces 7 days, health snapshots
   90 days. Purge within 24 h of expiry, and keep telemetry out of backups.
3. The health snapshot drops revenue amounts and personal goal, habit and task
   counts. It keeps only availability, grades and operational counts.
4. No existing dashboard (Grafana provisioning or
   `data-analytics-dashboard-web`) connects to a shared store until G2, G3 and
   G7 are fixed in their producers or configs and G5 and G6 have an owner decision.

None of these are accepted. No status, retention setting, dashboard
connection or runtime has been changed.
