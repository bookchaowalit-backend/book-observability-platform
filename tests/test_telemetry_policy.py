"""BOO-160: redacted telemetry schema, forbidden fields, redaction and retention.

Offline by default. Two optional source-drift checks run when a local
checkout path is supplied (they are skipped in CI):

- SYSTEM_HEALTH_SOURCE=/path/to/system_health.py (solo-empire 99ddc05c^ or later)
- PLATFORM_API_GATEWAY_SRC=/path/to/platform-api-gateway/src (exercises the
  real gateway telemetry sink)
"""

from __future__ import annotations

import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import sys
import threading
import unittest
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("telemetry_policy", ROOT / "scripts" / "telemetry_policy.py")
assert _SPEC is not None and _SPEC.loader is not None
policy = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(policy)

FIXTURES = ROOT / "fixtures" / "telemetry"
GATE = json.loads((ROOT / "fixtures" / "gates" / "telemetry-redaction-retention.json").read_text(encoding="utf-8"))
SCHEMA = policy.load_schema()
SIGNALS = ("log", "metric", "trace", "health_snapshot")
RAW_HEALTH = json.loads((FIXTURES / "raw" / "system-health-full.synthetic.json").read_text(encoding="utf-8"))
INVENTORY = GATE["sources"]["system_health"]["fields"]


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _variant(signal: str) -> dict[str, Any]:
    return SCHEMA["$defs"][signal]


def _valid(name: str) -> dict[str, Any]:
    return _load(FIXTURES / "valid" / f"{name}.json")


def _get(value: Any, path: str) -> list[Any]:
    """Resolve a dotted path with ``[]`` list expansion; returns every match."""

    nodes = [value]
    for part in path.split("."):
        expand = part.endswith("[]")
        key = part[:-2] if expand else part
        nxt: list[Any] = []
        for node in nodes:
            if isinstance(node, dict) and key in node:
                child = node[key]
                if expand:
                    nxt.extend(child if isinstance(child, list) else [])
                else:
                    nxt.append(child)
        nodes = nxt
    return nodes


def _leaves(value: Any) -> list[Any]:
    if isinstance(value, dict):
        return [leaf for child in value.values() for leaf in _leaves(child)]
    if isinstance(value, list):
        return [leaf for child in value for leaf in _leaves(child)]
    return [value]


class SchemaShapeTests(unittest.TestCase):
    def test_schema_uses_only_keywords_the_validator_implements(self) -> None:
        unsupported: set[str] = set()

        def walk(node: Any, in_properties: bool = False) -> None:
            if isinstance(node, dict):
                for key, child in node.items():
                    if not in_properties and key not in policy.SUPPORTED_KEYWORDS:
                        unsupported.add(key)
                    if key == "x-forbidden":
                        continue
                    walk(child, key in {"properties", "$defs"} and not in_properties)
            elif isinstance(node, list):
                for child in node:
                    walk(child)

        walk(SCHEMA)
        self.assertEqual(unsupported, set())

    def test_every_signal_is_a_closed_oneof_branch(self) -> None:
        refs = [branch["$ref"] for branch in SCHEMA["oneOf"]]
        self.assertEqual(refs, [f"#/$defs/{signal}" for signal in SIGNALS])
        for signal in SIGNALS:
            variant = _variant(signal)
            self.assertIs(variant["additionalProperties"], False, signal)
            self.assertEqual(variant["properties"]["signal"]["const"], signal)
            for field in ("schema_version", "signal", "retention_class", "service", "environment", "observed_at"):
                self.assertIn(field, variant["required"], f"{signal} must require {field}")

    def test_no_object_anywhere_is_open(self) -> None:
        def walk(node: Any, path: str) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False, f"{path} must be closed")
                for key, child in node.items():
                    walk(child, f"{path}/{key}")
            elif isinstance(node, list):
                for index, child in enumerate(node):
                    walk(child, f"{path}/{index}")

        walk(SCHEMA["$defs"], "#/$defs")

    def test_no_allowed_field_is_a_forbidden_key(self) -> None:
        forbidden = {policy._normalise_key(key) for key in SCHEMA["x-forbidden"]["keys"]}

        def walk(node: Any, path: str) -> None:
            if isinstance(node, dict):
                for key in node.get("properties", {}):
                    self.assertNotIn(policy._normalise_key(key), forbidden, f"{path}.{key} is allowed but forbidden")
                for key, child in node.items():
                    walk(child, f"{path}/{key}")

        walk(SCHEMA["$defs"], "#")

    def test_forbidden_value_patterns_compile(self) -> None:
        for name, pattern in SCHEMA["x-forbidden"]["value_patterns"].items():
            with self.subTest(name=name):
                re.compile(pattern)


class FixtureTests(unittest.TestCase):
    def test_valid_fixtures_pass(self) -> None:
        paths = sorted((FIXTURES / "valid").glob("*.json"))
        self.assertTrue(paths)
        seen = set()
        for path in paths:
            event = _load(path)
            seen.add(event["signal"])
            with self.subTest(fixture=path.name):
                self.assertEqual(policy.validate_event(event), [])
        self.assertEqual(seen, set(SIGNALS), "every signal needs a valid fixture")

    def test_invalid_fixtures_fail_for_the_stated_reason(self) -> None:
        paths = sorted((FIXTURES / "invalid").glob("*.json"))
        self.assertGreaterEqual(len(paths), 15)
        for path in paths:
            case = _load(path)
            with self.subTest(fixture=path.name):
                errors = policy.validate_event(case["event"])
                self.assertTrue(any(case["expect"] in error for error in errors), f"{case['expect']!r} not in {errors}")

    def test_invalid_fixtures_cover_every_signal(self) -> None:
        prefixes = {path.name.split("-")[0] for path in (FIXTURES / "invalid").glob("*.json")}
        self.assertEqual(prefixes, {"log", "metric", "trace", "health"})

    def test_cli_validate(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(policy.main(["validate", str(FIXTURES / "valid" / "log-request-completed.json")]), 0)
            self.assertEqual(policy.main(["validate", str(FIXTURES / "invalid" / "log-free-text-message.json")]), 1)


class ForbiddenFieldTests(unittest.TestCase):
    SAMPLES = {
        "email": "synthetic.person@example.invalid",
        "bearer_token": "Bearer synthetic0123456789token",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.c2ln",
        "provider_key": "sk_live_SYNTHETIC0123456789",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
        "ipv4": "203.0.113.7",
        "ipv6": "2001:db8::42",
        "currency_amount": "฿125,000",
        "phone": "+66 81 234 5678",
        "long_digit_run": "4111111111111111",
        "url": "https://example.invalid/callback?code=synthetic",
    }

    def test_every_value_pattern_has_a_sample(self) -> None:
        self.assertEqual(set(self.SAMPLES), set(SCHEMA["x-forbidden"]["value_patterns"]))

    def test_samples_are_flagged_in_any_string_field(self) -> None:
        base = _valid("log-request-completed")
        for name, sample in self.SAMPLES.items():
            for field in ("request_id", "route", "event", "service"):
                with self.subTest(pattern=name, field=field):
                    event = dict(base, **{field: sample})
                    errors = policy.validate_event(event)
                    self.assertIn(f"$.{field}: forbidden value ({name})", errors)

    def test_amounts_with_currency_codes_are_flagged(self) -> None:
        for sample in ("1,250.00 THB", "$40", "99 USD"):
            with self.subTest(sample=sample):
                self.assertIn("$.x: forbidden value (currency_amount)", policy.scan_forbidden({"x": sample}))

    def test_every_forbidden_key_is_rejected_at_top_level_and_nested(self) -> None:
        log = _valid("log-request-completed")
        metric = _valid("metric-requests-total")
        trace = _valid("trace-server-span")
        for key in SCHEMA["x-forbidden"]["keys"]:
            with self.subTest(key=key):
                errors = policy.validate_event(dict(log, **{key: "x"}))
                self.assertIn(f"$.{key}: forbidden key", errors)
                self.assertIn(f"$.{key} is not allowed", errors)
                labelled = copy.deepcopy(metric)
                labelled["labels"][key] = "x"
                self.assertIn(f"$.labels.{key}: forbidden key", policy.validate_event(labelled))
                attributed = copy.deepcopy(trace)
                attributed["attributes"][key] = "x"
                self.assertIn(f"$.attributes.{key}: forbidden key", policy.validate_event(attributed))

    def test_key_normalisation_catches_spelling_variants(self) -> None:
        for key in ("Net-Peer-IP", "net_peer_ip", "HTTP.URL", "Set-Cookie", "API-Key"):
            with self.subTest(key=key):
                self.assertTrue(policy.scan_forbidden({key: "x"}))

    def test_valid_fixtures_have_no_false_positives(self) -> None:
        for path in sorted((FIXTURES / "valid").glob("*.json")):
            with self.subTest(fixture=path.name):
                self.assertEqual(policy.scan_forbidden(_load(path)), [])

    def test_raw_numeric_amount_cannot_ride_in_a_metric_named_like_finance(self) -> None:
        for name in ("revenue_received", "pending_amount_thb", "Customer_Balance", "REVENUE_TOTAL"):
            with self.subTest(name=name):
                event = dict(_valid("metric-requests-total"), name=name)
                self.assertIn("$.name matches a disallowed pattern", policy.validate_event(event))


class HealthRedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.redacted = policy.redact_health_snapshot(copy.deepcopy(RAW_HEALTH))

    def test_redacted_snapshot_is_schema_valid(self) -> None:
        self.assertEqual(policy.validate_event(self.redacted), [])

    def test_redacted_snapshot_matches_committed_fixture(self) -> None:
        self.assertEqual(self.redacted, _valid("health-snapshot"))

    def test_raw_fixture_contains_what_must_be_removed(self) -> None:
        # Guard: the raw fixture must keep exercising every redaction rule.
        self.assertTrue(policy.scan_forbidden(RAW_HEALTH))
        self.assertIn("received", RAW_HEALTH["revenue"])
        self.assertIn("error", RAW_HEALTH["freshness"])
        self.assertIn("provider", RAW_HEALTH["credentials"]["calendar"])

    def test_dropped_values_never_reach_the_output(self) -> None:
        leaves = _leaves(self.redacted)
        rendered = json.dumps(self.redacted, ensure_ascii=False)
        for field in INVENTORY:
            if field["disposition"] != "drop":
                continue
            for value in _get(RAW_HEALTH, field["path"]):
                for leaf in _leaves(value):
                    with self.subTest(path=field["path"], value=leaf):
                        if isinstance(leaf, str):
                            self.assertNotIn(leaf, rendered)
                        elif isinstance(leaf, float):
                            self.assertNotIn(leaf, leaves)

    def test_kept_and_transformed_fields_reach_their_target(self) -> None:
        for field in INVENTORY:
            if field["disposition"] == "drop":
                continue
            if not _get(RAW_HEALTH, field["path"]):
                continue  # e.g. freshness counts when the raw section is an error
            with self.subTest(path=field["path"]):
                self.assertTrue(_get(self.redacted, field["target"]), f"{field['target']} missing")

    def test_every_raw_field_has_a_disposition(self) -> None:
        inventory = {field["path"] for field in INVENTORY}
        unmapped: list[str] = []

        def walk(node: Any, path: str) -> None:
            if path in inventory:
                return
            if isinstance(node, dict):
                for key, child in node.items():
                    walk(child, f"{path}.{key}" if path else key)
            elif isinstance(node, list):
                for child in node:
                    walk(child, f"{path}[]")
            else:
                unmapped.append(path)

        walk(RAW_HEALTH, "")
        self.assertEqual(unmapped, [])

    def test_section_errors_become_unavailable_without_text(self) -> None:
        raw = copy.deepcopy(RAW_HEALTH)
        raw["cron"] = {"error": "connection to 10.0.0.9 refused for synthetic@example.invalid"}
        raw["alerts"] = {"error": "alerts.py not found"}
        event = policy.redact_health_snapshot(raw)
        self.assertEqual(event["sections"]["cron"], {"available": False})
        self.assertEqual(event["sections"]["alerts"], {"available": False})
        self.assertEqual(policy.validate_event(event), [])

    def test_offset_timestamps_are_normalised_to_utc(self) -> None:
        raw = dict(copy.deepcopy(RAW_HEALTH), timestamp="2026-10-15T22:00:00+07:00")
        self.assertEqual(policy.redact_health_snapshot(raw)["observed_at"], "2026-10-15T15:00:00Z")

    def test_unknown_source_version_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            policy.redact_health_snapshot(dict(RAW_HEALTH, schema_version="2.0"))


class RetentionTests(unittest.TestCase):
    def test_one_retention_row_per_signal_matching_the_schema_class(self) -> None:
        rows = {row["signal"]: row for row in GATE["retention"]}
        self.assertEqual(set(rows), set(SIGNALS))
        for signal in SIGNALS:
            with self.subTest(signal=signal):
                row = rows[signal]
                self.assertEqual(row["retention_class"], _variant(signal)["properties"]["retention_class"]["const"])
                self.assertTrue(row["retention_class"].endswith(f"-{row['proposed_days']}d"))
                self.assertGreater(row["proposed_days"], 0)
                self.assertLessEqual(row["purge_sla_hours"], 24)
                self.assertEqual(row["backup"], "excluded")
                self.assertTrue(row["current"]["source"])

    def test_high_risk_signals_are_short_lived(self) -> None:
        rows = {row["signal"]: row for row in GATE["retention"]}
        self.assertLessEqual(rows["log"]["proposed_days"], 30)
        self.assertLessEqual(rows["trace"]["proposed_days"], rows["log"]["proposed_days"])

    def test_metric_retention_covers_widest_dashboard_window(self) -> None:
        rows = {row["signal"]: row for row in GATE["retention"]}
        widest = max(max(c.get("windows_days", [0])) for c in GATE["dashboard_consumers"])
        self.assertGreaterEqual(rows["metric"]["proposed_days"], widest)


class DashboardConsumerTests(unittest.TestCase):
    def test_grafana_labels_are_allowed_metric_labels(self) -> None:
        allowed = set(_variant("metric")["properties"]["labels"]["properties"])
        for consumer in GATE["dashboard_consumers"]:
            for label in consumer.get("labels", []):
                with self.subTest(label=label):
                    self.assertIn(label, allowed)

    def test_grafana_metric_names_are_allowed(self) -> None:
        base = _valid("metric-requests-total")
        for consumer in GATE["dashboard_consumers"]:
            for name in consumer.get("metrics", []):
                with self.subTest(metric=name):
                    self.assertEqual(policy.validate_event(dict(base, name=name)), [])


def _dict_keys(node: ast.AST) -> set[str]:
    keys: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            keys.update(k.value for k in child.keys if isinstance(k, ast.Constant) and isinstance(k.value, str))
    return keys


@unittest.skipUnless(os.environ.get("SYSTEM_HEALTH_SOURCE"), "set SYSTEM_HEALTH_SOURCE to a system_health.py to check source drift")
class SystemHealthSourceDriftTests(unittest.TestCase):
    """Every key the real producer emits must have a disposition in the gate fixture."""

    def test_inventory_covers_every_emitted_key(self) -> None:
        tree = ast.parse(Path(os.environ["SYSTEM_HEALTH_SOURCE"]).read_text(encoding="utf-8"))
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        segments_by_section: dict[str, set[str]] = {}
        for field in INVENTORY:
            head, _, rest = field["path"].partition(".")
            segments_by_section.setdefault(head, set()).update(part.rstrip("[]") for part in rest.split(".") if part)

        # full_health(): {'section': collect_x()} plus health['grade'] = {...}
        full = functions["full_health"]
        missing: list[str] = []
        for node in ast.walk(full):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                target = node.targets[0]
                if isinstance(target, ast.Name) and target.id == "health":
                    for key, value in zip(node.value.keys, node.value.values):
                        section = key.value
                        if section not in segments_by_section:
                            missing.append(section)
                            continue
                        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in functions:
                            for emitted in _dict_keys(functions[value.func.id]) - segments_by_section[section]:
                                missing.append(f"{section}.{emitted}")
                elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                    section = target.slice.value
                    for emitted in _dict_keys(node.value) - segments_by_section.get(section, set()):
                        missing.append(f"{section}.{emitted}")
        self.assertEqual(missing, [], "system_health emits fields with no redaction disposition")


@unittest.skipUnless(os.environ.get("PLATFORM_API_GATEWAY_SRC"), "set PLATFORM_API_GATEWAY_SRC to exercise the real gateway telemetry")
class GatewayTelemetryTests(unittest.TestCase):
    """Run platform-api-gateway's real request path and validate its telemetry events."""

    def setUp(self) -> None:
        sys.path.insert(0, os.environ["PLATFORM_API_GATEWAY_SRC"])
        from book_api_gateway.config import GatewayConfig
        from book_api_gateway.server import create_server

        self.events: list[dict[str, Any]] = []
        config = GatewayConfig(api_token="synthetic-gateway-token", upstream_base_url="http://127.0.0.1:9", upstream_timeout_seconds=0.2)
        self.server = create_server(config, telemetry_sink=self.events.append)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        sys.path.remove(os.environ["PLATFORM_API_GATEWAY_SRC"])

    def _call(self, path: str, headers: dict[str, str]) -> dict[str, Any]:
        before = len(self.events)
        try:
            urlopen(Request(self.base + path, headers=headers), timeout=5).read()
        except HTTPError as exc:
            with exc:
                exc.read()
        for _ in range(200):
            if len(self.events) > before:
                break
            threading.Event().wait(0.01)
        return policy.envelope_gateway_event(self.events[-1], observed_at="2026-10-15T08:00:00Z")

    def test_real_gateway_events_are_schema_valid(self) -> None:
        for path, headers in (
            ("/healthz", {}),
            ("/api/demo", {"Authorization": "Bearer synthetic-gateway-token"}),
            ("/api/demo", {"Authorization": "Bearer wrong-token"}),
        ):
            with self.subTest(path=path, auth=bool(headers)):
                event = self._call(path, headers)
                self.assertEqual(policy.validate_event(event), [])
                self.assertNotIn("synthetic-gateway-token", json.dumps(event))

    def test_gateway_field_set_matches_gate_inventory(self) -> None:
        event = self._call("/api/demo", {"Authorization": "Bearer synthetic-gateway-token"})
        emitted = set(event) - {"schema_version", "signal", "retention_class", "service", "environment", "observed_at", "level"}
        documented = {field["path"] for field in GATE["sources"]["gateway_request_completed"]["fields"]}
        self.assertEqual(emitted, documented)

    def test_client_supplied_ip_request_id_is_caught(self) -> None:
        # Gap G5: REQUEST_ID_RE accepts an IPv4 literal; only the value scan stops it.
        event = self._call("/healthz", {"X-Request-ID": "203.0.113.7"})
        self.assertEqual(event["request_id"], "203.0.113.7")
        self.assertIn("$.request_id: forbidden value (ipv4)", policy.validate_event(event))


if __name__ == "__main__":
    unittest.main()
