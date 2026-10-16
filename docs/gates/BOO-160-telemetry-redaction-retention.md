# BOO-160: redacted telemetry schema and retention

Status: **owner decision accepted 2026-10-16** (see the last section). The
schema and retention policy are accepted, and dashboard connection is deferred.
Nothing here connects a dashboard, applies a retention setting or moves a runtime.

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
| `#authentication-classes` | 63-65 | Provider credentials must not be written to responses, logs, tasks or payload metadata | `x-forbidden.keys` (token, authorization, api_key, secret, provider…) and `value_patterns` (bearer, Basic auth, JWT, Stripe/GitHub/Slack/AWS/Google/Anthropic/OpenAI keys, `ya29.` tokens, Telegram bot tokens, private keys). Keys are matched after camelCase splitting and as name components, so `accessToken` and `x-api-key` match. |
| `#bookfinance-api-v1` | 104-107 | Only redacted access metadata (subject, scope, route, status, query-key names); raw bearer tokens and payload values never persisted | Closed objects with no free-text field; `route` is a template or route class; amounts and currency strings rejected |

## What this change adds

| File | Purpose |
|---|---|
| [`schema/telemetry/redacted-telemetry-event.v1.schema.json`](../../schema/telemetry/redacted-telemetry-event.v1.schema.json) | JSON Schema (2020-12) allow-list: one `log`, `metric`, `trace` or `health_snapshot` per document. Every object is `additionalProperties: false`; there is no free-text field. `x-forbidden` lists forbidden keys and value patterns. Fields pinned to a closed hex/UUID format (trace, span, correlation and request IDs, `subject_hash`) skip the value scan only when they already match that format, because random hex can look like a digit run. Bare domains count as URLs only when a path follows and they do not sit inside a dotted name or route, so names like `platform.app`, `kubernetes.io` and `/mnt/data.io` pass. |
| [`scripts/telemetry_policy.py`](../../scripts/telemetry_policy.py) | Dependency-free validator for that schema plus the `x-forbidden` scan, and `redact_health_snapshot()` which maps the real `system_health.full_health()` payload onto the allow-list. |
| [`fixtures/gates/telemetry-redaction-retention.json`](../../fixtures/gates/telemetry-redaction-retention.json) | Machine-readable gate record: contract references, retention table, dashboard consumers, and the per-field source inventory with a disposition (keep / transform / drop) and `file:line` for each field. |
| `fixtures/telemetry/{valid,invalid,raw}/` | Synthetic events only. 13 valid, 45 invalid (each with the expected rejection reason), a synthetic raw `system_health` payload, and synthetic PR #1 access-log lines modelled on its real output. |
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
`subject_hash` are kept. `request_id` must be server-generated (uuid4 hex or a
canonical UUID); a client-supplied `X-Request-ID` that the gateway echoes is
rejected (G5).

### Logs, spans and metrics from PR #1 (`platform_observability.instrument()`)

PR #1 in this repository (unmerged, branch `codex/shared-infrastructure-20261015`)
adds `src/platform_observability/`. A review probe of its real output found
shapes the first version of this schema rejected. Each is now handled:

| PR #1 output | Handling here |
|---|---|
| Starlette route templates `{item_id:int}`, `{path:path}`, trailing `/`, `/.well-known/...` (middleware `_ROUTE`) | Schema `route` accepts converter segments, an optional trailing `/` and dot-first literal segments. Literal segments must still start with a letter, so raw numeric IDs stay rejected. |
| Access-log line with no `event` / `level` / envelope | Not widened. The collector wraps each line with `envelope_access_log()`, which adds the envelope, the fixed event `http.request` and a `level` derived from status. Producer fields that collide with the envelope are refused. |
| `service_name` matching `[A-Za-z0-9_.-]{1,64}` (e.g. `Shared_API`) | Schema `service` uses the same character set. |
| `instance` relabelled to the pod name, no port (`config/prometheus.yaml`) | `labels.instance` takes a name with an optional `:port`. IP literals are still rejected. |
| Span resource attributes `telemetry.sdk.*`, `service.instance.id` | Added to the trace attribute allow-list. |
| `duration_seconds` above 3600 (not bounded by PR #1) | **Open for the owner (G10).** Requests longer than an hour fail validation. |

`fixtures/telemetry/raw/pr1-access-log.synthetic.json` and the `*-pr1-*` valid
fixtures model this output, and run in CI. `PR1RuntimeTelemetryTests` runs the
real `instrument()` on a FastAPI app with those routes and validates every log
line, span and `/metrics` sample. It skips until PR #1's package and its test
dependencies are importable, and runs under PR #1's pytest workflow once both
are merged. On a local test merge of PR #1 at `e2d1ab3` (Python 3.12), all three
pass. This branch is cut from `main` and touches none of PR #1's files.

### Existing dashboards

| Consumer | Source | What it reads | Constraint on this gate |
|---|---|---|---|
| `bookchaowalit-ai/data-analytics-dashboard-web` @ `1f35f42` | `lib/analytics.ts:20-24`, README "CSV contract" | Browser-only CSV with `timestamp`, `segment`, `value`. Windows: 24H / 7D / 30D | Metric retention must be at least 30 days. If it is ever fed from this platform, `segment` must be a schema label value, never a person or customer. Today it reads no telemetry store. |
| Grafana provisioning (solo-empire @ `b606a119`) | `grafana/provisioning/dashboards/{service-overview,system-metrics,mlops-reference}.json` | `up`, `node_*`, `traefik_service_requests_total`, `ALERTS`, `solo_empire_mlops_*`. Labels: `mode, fstype, mountpoint, device, cpu, service, code, alertstate, alertname, job, model_name, model_version` | Every metric name and label is on the allow-list (tested). `instance` must be a service or pod name with an optional `:port`; IP literals and `/home/*` mountpoints are rejected. |

## Retention policy (accepted 2026-10-16)

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
| G1 | No redaction code exists on `main` of this repository today. The redactor here covers health snapshots only. Logs and traces depend on producers emitting allow-listed fields. **This changes once PR #1 lands:** its `instrument()` becomes the platform's log/span/metric producer, and `PR1RuntimeTelemetryTests` then checks its real output against this schema. | `git ls-tree origin/main`; PR #1 |
| G2 | `telemetry.ts` sets `http.route` to the raw `url.pathname` and copies `error.message` into the span status. `HttpInstrumentation` adds the full URL, peer IP and user agent. The schema rejects all of these, but nothing in the source strips them yet. | telemetry.ts:34, 70-73; server.ts:524 |
| G3 | `system_health.py` returns `str(e)` for cron, freshness and alert failures, and `--save` persists raw revenue amounts. | :117, :135, :154, :381-387 |
| G4 | `system_health.py` timestamps are naive local time. The redactor reads them as Asia/Bangkok, the host zone (override with `assume_tz=` or `--assume-tz`), and converts to UTC. If the host zone changes, the redactor has to be told. | :178 |
| G5 | The gateway echoes a client-supplied `X-Request-ID` matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, which admits IP literals and arbitrary IDs. The schema now accepts only server-generated IDs, so those gateway events are **rejected** until the gateway hashes or replaces client IDs (proved against the real gateway in CI). | gateway server.py:26, 134-138 |
| G6 | `subject_hash` is an unkeyed `sha256(token)[:16]`. It is a stable pseudonym, linkable across events and across 14 days of logs. A keyed HMAC with rotation is not designed here. | gateway server.py:229 |
| G7 | Loki has no retention and Tempo's volume path does not match its storage path. Neither is changed here. | see table |
| G8 | Alertmanager notification history, Grafana annotations and the audit log are not covered. `audit_log` retention ("centralized audit retention", contract line 163) still needs its own decision. | contract:163 |
| G9 | The gateway tests run in CI against the public `platform-api-gateway` pinned at `6e1fb34` (`REQUIRE_GATEWAY_TESTS=1` turns a missing checkout into a failure). The `system_health` drift check needs private solo-empire and stays a local one-off check, frozen at `99ddc05c`: the producer no longer exists at solo-empire HEAD. | `.github/workflows/check.yml`; tests |
| G10 | PR #1 emits no envelope (`schema_version`, `signal`, `retention_class`, `environment`, `observed_at`), and its `duration_seconds` is unbounded while the schema caps it at 3600. The owner decides whether the envelope is added by a collector adapter (as modelled here) or by PR #1 itself, and whether to keep the cap. | PR #1 middleware.py |

## Verification

```bash
bash scripts/check.sh
# as CI runs it (gateway tests required):
REQUIRE_GATEWAY_TESTS=1 PLATFORM_API_GATEWAY_SRC=/path/platform-api-gateway/src bash scripts/check.sh
# local one-off, frozen source:
SYSTEM_HEALTH_SOURCE=/path/system_health.py python3 -m unittest -v tests.test_telemetry_policy
# health snapshot from a raw system_health JSON (naive times read as Asia/Bangkok):
python3 scripts/telemetry_policy.py redact-health --assume-tz Asia/Bangkok RAW.json
```

The tests fail if:

- a valid fixture breaks the schema, or an invalid fixture passes or fails for a different reason;
- any forbidden key (top level, metric label, span attribute) or forbidden value pattern is accepted;
- an allowed field is itself a forbidden key, or any object is left open;
- legitimate values are rejected: 20,000 random uuid4 correlation/request IDs and 20,000 span/trace IDs (a quarter forced all-digit), dotted service/event/label names and routes such as `/api/rates/usd1`;
- `redact_health_snapshot()` output stops validating, changes from the committed fixture, or leaks a dropped value;
- a raw `system_health` field has no disposition, or (with `SYSTEM_HEALTH_SOURCE`) the real producer emits a key the inventory does not cover;
- a retention row is missing or mismatched for a signal, or metric retention falls below the widest dashboard window;
- a Grafana metric or label used today is not on the allow-list;
- (CI, `PLATFORM_API_GATEWAY_SRC`) a real gateway event is not schema-valid, its field set drifts from the inventory, or a client-supplied request ID is accepted;
- PR #1-shaped log lines stop validating after `envelope_access_log()`, or (once PR #1 is importable) the real `instrument()` output does not validate;
- naive `system_health` times are not read as Asia/Bangkok by default.

## Owner decision — ACCEPTED (owner decision 2026-10-16)

Owner's answer, verbatim: "ทั้งหมด ยกเว้น 140/256 (Recommended)". That is, accept the recommended option on every pending gate decision except BOO-140 and BOO-256. It was relayed via the parent session (`local_a6dedf75`). For BOO-160 the relayed decision reads: "accept telemetry schema + retention 30/14/7/90 days; defer dashboards."

Accepted options (text unchanged from the proposal):

1. Telemetry reaching this platform must validate against
   `observability.telemetry.v1` (this schema) **after collector-side
   enveloping** (`envelope_access_log()` / `envelope_gateway_event()`). The
   schema is an allow-list, has no free-text field, and the `x-forbidden` scan
   stays on even if an object is opened later. Today, PR #1 output (synthetic
   fixtures plus a local test merge) validates once wrapped. Gateway events
   validate except when they carry a client-supplied request ID (G5). The owner
   still has to decide G10.
2. Retention: metrics 30 days, logs 14 days, traces 7 days, health snapshots
   90 days. Purge within 24 h of expiry, and keep telemetry out of backups.
3. The health snapshot drops revenue amounts and personal goal, habit and task
   counts. It keeps only availability, grades and operational counts.
4. No existing dashboard (Grafana provisioning or
   `data-analytics-dashboard-web`) connects to a shared store until G2, G3 and
   G7 are fixed in their producers or configs and G5 and G6 have an owner decision.

### Still open after the decision

The owner did not decide these, so they stay open:

- **G10:** whether the collector adapter or PR #1 itself adds the envelope, and
  whether to keep the 3600 s `duration_seconds` cap. Option 1 above names G10
  as an owner decision still to make, so accepting option 1 does not decide it.
- **G5 and G6:** gateway client-supplied `X-Request-ID` handling, and the
  unkeyed `subject_hash`. Option 4 makes their owner decisions a precondition
  for any dashboard connection.
- **G2, G3 and G7:** producer and config fixes (telemetry.ts attributes,
  system_health error text and saved amounts, Loki/Tempo retention and storage).
  They are needed before any dashboard connects (option 4).
- **G8:** audit_log and Alertmanager history retention.
- **G1 and G9:** test coverage notes, unchanged.

Accepting the decision changes no runtime. Retention is not yet applied to
Prometheus, Loki or Tempo, no dashboard is connected, and the registry status
is unchanged.
