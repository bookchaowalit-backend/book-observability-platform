# Contract surface: book-observability-platform

This page documents the API, event, CLI, storage and configuration surface that
`book-observability-platform` owns or consumes. The machine-readable list is `interfaces` in
[`contract.json`](../contract.json); `scripts/check.py` fails when an interface
listed there is missing from this page.

- Platform: `observability` (contract `book-platform.contract.v1`, API `v1`)
- Status: `scaffolded`; source status: `current-implementation-in-solo-empire`
- Current implementation: `solo-empire` at `infra/self-hosted-stack`, `infra/tests/platform`
- Depends on: none

Interfaces marked `current-in-solo-empire` are served by the `solo-empire`
control plane today. This repository does not serve them yet; they are the
compatibility surface a migration must preserve. The `source` column is a path
in the implementing repository.

## Interfaces

| ID | Kind | Direction | Interface | Contract | Auth | Source | Status |
|---|---|---|---|---|---|---|---|
| `observability.event.otlp-traces` | event | consumes | OTLP/HTTP traces to http://localhost:4318/v1/traces (Tempo), opt-in via OTEL_ENABLED=true | - | - | `infra/api/telemetry.ts` | current-in-solo-empire |
| `observability.http.api-health` | http | consumes | `GET /health on solo-empire-api` | - | - | `infra/api/server.ts` | current-in-solo-empire |
| `observability.config.compose-profile` | config | provides | docker compose profile `observability` (Prometheus, Grafana, Loki, Tempo, Alertmanager, exporters) | - | - | `infra/self-hosted-stack/docker-compose.yml` | current-in-solo-empire |

## Behaviour notes

Derived from the current source; re-check the source before changing a
consumer.

- Traces are opt-in (`OTEL_ENABLED=true`); the service name defaults to
  `solo-empire-api` and spans carry `http.method` and `http.route`. The
  exporter endpoint is `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `http://localhost:4318/v1/traces`.
- `GET /health` returns `status`, `service`, `version` and `timestamp`.
- The Compose `observability` profile runs Prometheus, Grafana, Loki, Tempo,
  Alertmanager, node-exporter, Pushgateway, blackbox-exporter and Graphite in
  the local lab. It is not production infrastructure.
- Telemetry must be redacted before it reaches this platform (no tokens,
  request bodies or private payloads).

## Migration gates

- telemetry redaction
- retention policy
- alert drill

## Out of scope

No production provider integration, credential, database writer or customer
payload lives in this repository. Record parity, privacy and rollback evidence
in the parent platform registry before any cutover.
