#!/usr/bin/env python3
"""Observe prebuilt policy-client and policy-gate against fresh synthetic state.

No builds, compiler invocations, downloads or external endpoints are required.
The relay forwards to the real gate; it never synthesizes an admission result.
Only the lost-response fixture withholds one already received real response.
"""
import argparse
import base64
import copy
import importlib.util
import json
import os
import platform
import re
import socket
import stat
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("artifact_gate_expectations", PROJECT / "tools/verify-artifact-gate.py")
ARTIFACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACT)
require, encoded, sha, utc = ARTIFACT.require, ARTIFACT.encoded, ARTIFACT.sha, ARTIFACT.utc
MAX_RESPONSE = 64 << 20
SUMMARY_SCHEMA = "policy-studio/gate-client-summary/v1"
VIEW_SCHEMA = "policy-studio/admission-view/v2"
OUTCOME_SCHEMA = "policy-studio/admission-outcome/v2"
COMMAND_FIELDS = {"request_id", "expected_revision", "policy_version", "idempotency_key"}
ERROR_CODES = {"lost_response_after_real_commit": "TRANSPORT_UNCERTAIN", "invalid_token_401": "UNAUTHORIZED",
    "stale_prepared_command": "CONFLICT", "unknown_command_field": "COMMAND_INVALID",
    "existing_report_preserved": "REPORT_FILE_UNAVAILABLE", "unsafe_token_mode": "TOKEN_FILE_INVALID",
    "symlink_token_rejected": "TOKEN_FILE_INVALID", "fifo_token_nonblocking_rejection": "TOKEN_FILE_INVALID",
    "caller_revision_override": "USAGE_INVALID", "prepare_absent_request": "REQUEST_NOT_PENDING",
    "existing_command_preserved": "COMMAND_FILE_UNAVAILABLE", "redirect_not_followed": "REDIRECT_REJECTED"}


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate public JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def private_file(path, raw):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "fixture private file mode differs")


def inventory():
    result = ARTIFACT.source_inventory(PROJECT)
    paths = [Path(__file__).resolve()]
    paths.extend(PROJECT / "examples/gate-client" / name for name in
                 ["bootstrap.json", "artifact-allow.json", "artifact-deny.json", "artifact-changed.json"])
    for package in [PROJECT / "cmd/policy-client", PROJECT / "internal/gateclient"]:
        paths.extend(p for p in sorted(package.rglob("*")) if p.is_file() and not p.name.endswith("_test.go"))
    require(any(p.suffix == ".go" for p in paths), "client production source is absent")
    for path in paths:
        raw = path.read_bytes()
        result[str(path.relative_to(PROJECT))] = {"sha256": sha(raw), "bytes": len(raw)}
    return result


class Observer(ARTIFACT.Runner):
    def __init__(self, gate, client, proof):
        super().__init__(gate, proof)
        self.client = client
        self.gate_start_attempts = 0
        self.gate_started = 0

    def check_private_snapshot(self, raw, token, principal):
        # This private store must retain its authentication digest. It is never
        # copied into stdout, a report or the public proof. Public secret_free
        # remains stricter and rejects both plaintext and credential digests.
        require(token.encode() not in raw, "private snapshot stored credential plaintext")
        snapshot = parse(raw)
        require(snapshot["schema"] == "policy-studio/admission-snapshot/v2" and
                snapshot["principals"] == [{**principal, "token_sha256": sha(token.encode())}],
                "private snapshot does not bind the fresh CLI credential correctly")

    def init(self, directory, config, name, accepted=True):
        directory.mkdir(mode=0o700)
        source = directory / "operator-bootstrap.json"
        source.write_bytes(encoded(config))
        state, credential = directory / "state", directory / "private.token"
        began = utc()
        result = subprocess.run([str(self.binary), "-init", str(source), "-state", str(state),
                                 "-token-file", str(credential)], capture_output=True, timeout=20)
        # Record only safe process metadata before validating private outputs,
        # so a failed check cannot erase an already executed initialization.
        record = {"case": name, "kind": "initialization", "expected_accepted": accepted,
                  "exit_code": result.returncode, "started_at_utc": began, "finished_at_utc": utc(),
                  "state_created": state.exists(), "credential_created": credential.exists()}
        self.proof["observations"].append(record)
        token = credential.read_text().strip() if credential.exists() else None
        if token:
            self.tokens.append(token)
        self.secret_free(result.stdout + result.stderr)
        record.update({"stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
                       "operator_file_sha256": sha(source.read_bytes())})
        require((result.returncode == 0) == accepted, name + ": unexpected initialization exit")
        if accepted:
            require(token is not None and len(token) == 64 and all(c in "0123456789abcdef" for c in token),
                    name + ": no valid fresh CLI credential")
            modes = {"credential": stat.S_IMODE(credential.stat().st_mode),
                     "state": stat.S_IMODE(state.stat().st_mode),
                     "snapshot": stat.S_IMODE((state / "snapshot.json").stat().st_mode)}
            require(modes == {"credential": 0o600, "state": 0o700, "snapshot": 0o600},
                    name + ": private file modes differ")
            self.check_private_snapshot((state / "snapshot.json").read_bytes(), token, config["principals"][0])
            record.update({"private_modes": modes, "private_snapshot_credential_binding_checked": True,
                           "private_snapshot_recorded": False})
        else:
            require(not state.exists() and not credential.exists(), name + ": rejected init wrote private state")
        return state, token

    def start(self, state, name):
        self.gate_start_attempts += 1
        result = super().start(state, name)
        self.gate_started += 1
        return result

    def secret_free(self, raw):
        for token in self.tokens:
            require(token.encode() not in raw and sha(token.encode()).encode() not in raw,
                    "private credential or credential hash appeared in recorded output")

    def invoke(self, case, args, expected_exit, status=None, http_status=None, env=None):
        began = utc()
        result = subprocess.run([str(self.client)] + args, capture_output=True, timeout=20,
                                env=env if env is not None else os.environ.copy())
        record = {"case": case, "kind": "actual_client_process", "started_at_utc": began,
                  "finished_at_utc": utc(), "expected_exit_code": expected_exit, "exit_code": result.returncode}
        self.proof["observations"].append(record)
        self.secret_free(result.stdout + result.stderr)
        require(len(result.stdout) <= 16 << 10 and len(result.stderr) <= 16 << 10,
                case + ": terminal output exceeded summary bound")
        require(result.returncode == expected_exit, case + ": literal client exit differs")
        summary = None
        if status is not None:
            require(result.stderr == b"", case + ": structured command leaked separate stderr output")
            summary = parse(result.stdout)
            ARTIFACT.assert_public(summary)
            require(summary["schema"] == SUMMARY_SCHEMA and summary["status"] == status and
                    (http_status is None or summary["http_status"] == http_status), case + ": literal public summary differs")
            require(set(summary).issubset({"schema", "action", "status", "http_status", "server_schema",
                                          "replayed", "outcome_id", "reason", "claim_counts", "code", "scope"}) and
                    {"schema", "action", "status", "http_status", "server_schema", "replayed",
                     "outcome_id", "reason", "scope"}.issubset(summary),
                    case + ": terminal summary field boundary differs")
            require(isinstance(summary["scope"], str) and summary["scope"], case + ": summary has no local scope")
            code = "SERVER_INVALID" if case.startswith("server_URL_boundary_") else ERROR_CODES.get(case)
            if code is not None:
                require(summary.get("code") == code and summary["outcome_id"] == "" and
                        summary["replayed"] is False and "claim_counts" not in summary,
                        case + ": local/transport failure was confused with an authoritative admission result")
            require(b"artifact_base64" not in result.stdout and b"changed-after-init" not in result.stdout and
                    b"payments" not in result.stdout and b"ap-northeast-2" not in result.stdout,
                    case + ": terminal output disclosed synthetic private artifact values")
            require(all(needle not in result.stdout for needle in
                        [b'"artifact_base64"', b'"destination"', b'"prepare_export"', b'"jsonl"']),
                    case + ": terminal output disclosed demo artifact values")
        record.update({"stdout": result.stdout.decode("utf-8"),
            "stderr": result.stderr.decode("utf-8"), "stdout_sha256": sha(result.stdout),
            "stderr_sha256": sha(result.stderr), "summary": summary})
        return summary

    def http(self, base, token, method, path, raw=None):
        # Avoid proxies and redirects in the observer independently of the client.
        from urllib.error import HTTPError
        from urllib.request import ProxyHandler, Request, build_opener
        opener = build_opener(ProxyHandler({}), ARTIFACT.NoRedirect())
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
        began, wall = utc(), time.time()
        try:
            with opener.open(Request(base + path, data=raw, headers=headers, method=method), timeout=15) as reply:
                status, body = reply.status, reply.read(MAX_RESPONSE + 1)
        except HTTPError as reply:
            status, body = reply.code, reply.read(MAX_RESPONSE + 1)
        require(len(body) <= MAX_RESPONSE, "observer response exceeded v2 contract byte bound")
        self.secret_free(body)
        parsed = parse(body)
        ARTIFACT.assert_public(parsed)
        return {"status": status, "method": method, "path": path, "started_at_utc": began,
                "finished_at_utc": utc(), "wall_start_unix": wall, "wall_finish_unix": time.time(),
                "response_sha256": sha(body), "raw_response_body": body.decode("utf-8"), "response": parsed}


class LocalFixture:
    """A bounded loopback transport fixture; admission responses come from gate."""
    def __init__(self, observer, mode="relay", gate=None, token=None, location=None):
        self.observer, self.mode, self.gate, self.token, self.location = observer, mode, gate, token, location
        self.records, self.errors = [], []
        self.lock = threading.Lock()
        self.drop_next_success = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def do_GET(self):
                self.handle_bounded()

            def do_POST(self):
                self.handle_bounded()

            def handle_bounded(self):
                try:
                    require(self.path in {"/api/state", "/api/admit"}, "fixture unexpected path")
                    length = int(self.headers.get("Content-Length", "0"))
                    require(0 <= length <= 4096, "fixture oversized client command")
                    raw = self.rfile.read(length) if length else None
                    if fixture.mode == "relay":
                        require(self.headers.get("Authorization") == "Bearer " + fixture.token,
                                "relay received an unexpected private credential")
                        record = fixture.observer.http(fixture.gate, fixture.token, self.command, self.path, raw)
                        if raw is not None:
                            fixture.observer.secret_free(raw)
                            record["command_bytes_sha256"] = sha(raw)
                            record["raw_command_body"] = raw.decode("utf-8")
                            record["command"] = parse(raw)
                        body, status = record["raw_response_body"].encode(), record["status"]
                    else:
                        status = 302 if fixture.mode == "redirect" else 503
                        body = encoded({"error": "TRANSPORT_FIXTURE"}) + b"\n"
                        record = {"status": status, "method": self.command, "path": self.path,
                                  "response_sha256": sha(body), "raw_response_body": body.decode(),
                                  "response": parse(body), "fixture_only": True}
                    with fixture.lock:
                        drop = fixture.drop_next_success and self.command == "POST" and status == 200
                        if drop:
                            fixture.drop_next_success = False
                        record["response_withheld"] = drop
                        fixture.records.append(record)
                    if drop:
                        # Real gate has returned a committed outcome. No response
                        # headers or body reach the client, and no second POST occurs.
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    if fixture.mode == "redirect":
                        self.send_header("Location", fixture.location + self.path)
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as error:
                    with fixture.lock:
                        fixture.errors.append(type(error).__name__)
                    self.close_connection = True

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.address = "http://127.0.0.1:" + str(self.server.server_port)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        require(not self.thread.is_alive() and not self.errors, "loopback fixture failed or did not stop")

    def mark(self):
        with self.lock:
            return len(self.records)

    def since(self, mark):
        with self.lock:
            return copy.deepcopy(self.records[mark:])


def flags(action, base, credential, command, report=None, request=None, key=None):
    args = [action, "--server", base, "--token-file", str(credential), "--command-file", str(command)]
    if action == "prepare":
        args += ["--request-id", request, "--idempotency-key", key]
    if report is not None:
        args += ["--report-file", str(report)]
    return args


def summary_outcome(summary, result, status, approved):
    out = result["outcome"]
    require(summary["action"] == "submit" and summary["http_status"] == status and
            summary["server_schema"] == OUTCOME_SCHEMA and summary["replayed"] == result["replayed"] and
            summary["outcome_id"] == out["id"] and summary["reason"] == ("ADMITTED" if approved else "EVIDENCE_REJECTED") and
            summary["claim_counts"] == {"total": 5, "pass": 5 if approved else 0, "fail": 0 if approved else 5,
                                        "unsupported": 0, "truncated": 0, "unknown": 0},
            "public summary differs from literal authoritative outcome")


def report_result(observer, report, http, expected_status):
    require(report.exists() and stat.S_IMODE(report.stat().st_mode) == 0o600 and report.is_file(), "private report missing or mode differs")
    raw = report.read_bytes()
    observer.secret_free(raw)
    require(raw == http["raw_response_body"].encode() and http["status"] == expected_status,
            "private report differs from actual server response bytes")
    observer.proof["private_report_observations"].append({"path": str(report), "mode": "0600",
        "bytes": len(raw), "sha256": sha(raw), "matches_actual_server_bytes": True})
    return http["response"] if expected_status == 200 else http["response"]["result"]


def record_transport(observer, name, records, methods):
    require([r["method"] for r in records] == methods, name + ": actual client request sequence differs")
    for index, record in enumerate(records):
        record.update({"case": name, "index": index, "kind": "actual_gate_response_via_relay"})
        observer.proof["transport_observations"].append(record)


def unchanged_POST(records, saved):
    require(len(records) == 1 and records[0]["method"] == "POST" and
            records[0]["raw_command_body"].encode() == saved and
            records[0]["command_bytes_sha256"] == sha(saved) and
            records[0]["command"] == parse(saved) and set(records[0]["command"]) == COMMAND_FIELDS,
            "submit did not send the exact unchanged four-field prepared bytes once")


def fixture(directory, lost):
    if lost:
        declared = ARTIFACT.declaration(int(time.time()))
        cases = [declared[0], declared[7]]
        return cases, ARTIFACT.bootstrap(directory, cases)
    example = PROJECT / "examples/gate-client"
    config = parse((example / "bootstrap.json").read_bytes())
    expected_claims = ["action_equal", "destination_equal", "row_limit_equal", "dry_run_equal", "format_equal"]
    require([c["id"] for c in config["preflight"]["recipe"]["claims"]] == expected_claims and
            [r["key"] for r in config["requests"]] == ["req-client-allow", "req-client-deny"] and
            config["preflight"]["max_age_seconds"] == 60,
            "literal two-request documented example differs")
    changed = (example / "artifact-changed.json").read_bytes()
    require(parse(changed) == {"schema": "gooo/export-plan/v1", "action": "prepare_export",
                              "destination": "external", "row_limit": 500, "dry_run": True, "format": "jsonl"},
            "documented changed artifact is not the literal synthetic denial input")
    cases = []
    for name, filename, request in [("ready", "artifact-allow.json", "req-client-allow"),
                                    ("digest", "artifact-deny.json", "req-client-deny")]:
        raw = (example / filename).read_bytes()
        require(sha(raw) == "462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533" and
                parse(raw) == {"schema": "gooo/export-plan/v1", "action": "prepare_export", "destination": "internal",
                               "row_limit": 500, "dry_run": True, "format": "jsonl"},
                "documented artifact byte identity or literal values differ")
        path = directory / filename
        private_file(path, raw)
        requirement = next(a for a in config["artifacts"] if a["request_id"] == request)
        requirement["path"] = str(path)
        cases.append({"case": name, "request_id": request, "path": path,
                      "statuses": ["pass"] * 5 if name == "ready" else ["fail"] * 5,
                      "status": 200 if name == "ready" else 403,
                      "reason": "ADMITTED" if name == "ready" else "EVIDENCE_REJECTED",
                      "raw": raw, "observed_raw": raw if name == "ready" else changed})
    return cases, config


def verify_case(sources, case, command, config, http):
    """Full literal checks over a real result; no caller-supplied pass fields."""
    require(http["status"] == case["status"], "literal real gate status differs")
    result = http["response"] if case["status"] == 200 else http["response"]["result"]
    out, approved = result["outcome"], case["status"] == 200
    require(result["replayed"] is False and out["schema"] == OUTCOME_SCHEMA and out["command"] == command and
            out["committed"] == approved and out["prior_revision"] == 1 and out["new_revision"] == (2 if approved else 1),
            "actual fresh outcome or local transition differs")
    copied = copy.deepcopy(out)
    copied["id"] = ""
    require(out["id"] == ARTIFACT.digest(encoded(copied)), "whole real outcome byte identity differs")
    preflight, recipe = out["preflight"], config["preflight"]["recipe"]
    producer, context = preflight["producer"], preflight["context"]
    requirement = next(a for a in config["artifacts"] if a["request_id"] == case["request_id"])
    operator = config["principals"][0]
    principal = {k: operator[k] for k in ["key", "team", "active", "enabled", "can_execute"]}
    require(context["command"] == command and context["artifact"] == requirement and context["principal"] == principal and
            context["request"] == {"request": next(r for r in config["requests"] if r["key"] == case["request_id"]),
                                   "status": "pending", "revision": 1} and
            context["policy_version"] == command["policy_version"] == out["policy_version"] and
            out["principal_key"] == principal["key"], "server-owned execution context differs")
    require(preflight["context_sha256"] == ARTIFACT.digest(encoded(context)) == producer["context_digest"],
            "whole execution-context byte identity differs")
    implementation = ARTIFACT.verify_provenance(PROJECT, preflight, sources)
    raw = base64.b64decode(producer["artifact_base64"], validate=True)
    require(raw == case["observed_raw"] and base64.b64encode(raw).decode() == producer["artifact_base64"] and
            producer["actual_sha256"] == ARTIFACT.digest(raw) and producer["byte_count"] == len(raw) and
            producer["observed_size"] == len(raw) and producer["acquisition_status"] == "read_success" and
            producer["expected_sha256"] == requirement["expected_sha256"] and
            producer["recipe_sha256"] == ARTIFACT.digest(encoded(recipe)) and
            (producer["digest_ok"], producer["schema_ok"], producer["types_ok"]) == (approved, True, True) and
            producer["artifact_reason"] == ("ARTIFACT_VERIFIED" if approved else "ARTIFACT_DIGEST_MISMATCH"),
            "literal actual artifact bytes or mandatory guards differ")
    require(int(http["wall_start_unix"]) <= producer["observation_unix"] <= preflight["decision_unix"] <=
            int(http["wall_finish_unix"]) and preflight["decision_unix"] < requirement["deadline_unix"],
            "actual observation and decision-time interval differs")
    claims = recipe["claims"]
    require(len(claims) == len(producer["observations"]) == 5, "five required claims were reduced")
    values = parse(raw)
    base = copy.deepcopy(producer)
    base["observations"] = []
    base_digest = ARTIFACT.digest(encoded({"domain": "policy-studio/artifact-observation-base/v1", "report": base}))
    for i, (claim, observation) in enumerate(zip(claims, producer["observations"])):
        value = values[claim["field"]]
        actual = "true" if value is True else "false" if value is False else str(value)
        expected = {"claim_id": claim["id"], "verifier": "field_equals/v1", "field": claim["field"],
                    "expected": claim["expected"], "actual": actual, "status": case["statuses"][i],
                    "reason": "FIELD_EQUALS" if approved else "ARTIFACT_DIGEST_MISMATCH", "evidence_id": ""}
        claim_digest = ARTIFACT.digest(encoded({"domain": "policy-studio/artifact-claim/v1",
                                                "base_sha256": base_digest, "observation": expected}))
        expected["evidence_id"] = "ev_" + claim_digest[7:]
        require(observation == expected, "full ordered predicate result and evidence identity differ")
    expected_claims = [c["id"] for c in claims]
    require([e["claim_id"] for e in preflight["evidence"]] == expected_claims, "Gooo evidence omitted a required claim")
    for evidence, status in zip(preflight["evidence"], case["statuses"]):
        require(evidence["facts"] == {"actual_authority": "live-observation", "required_authority": "live-observation",
            "status": status, "confidence": "observed", "provider_verified": True,
            "observed_binding": preflight["context_sha256"], "required_binding": preflight["context_sha256"],
            "observed_artifact": producer["actual_sha256"], "required_artifact": requirement["expected_sha256"],
            "observed_policy": command["policy_version"], "required_policy": command["policy_version"],
            "observed_at_unix": producer["observation_unix"], "now_unix": preflight["decision_unix"],
            "max_age_seconds": config["preflight"]["max_age_seconds"], "expires_at_unix": requirement["deadline_unix"]} and
            evidence["decision"] == {"admissible": approved, "reason": "ADMISSIBLE" if approved else "EVIDENCE_INCOMPLETE",
                "provider_ok": True, "evidence_ok": approved, "authority_ok": True, "binding_ok": True,
                "artifact_ok": approved, "policy_ok": True, "freshness_ok": True, "deadline_ok": True},
                "whole typed compiled evidence decision differs")
    completion = preflight["completion"]
    policy = {"schema": "policy-studio/completion-policy/v1", "policy_id": config["preflight"]["id"],
              "revision": config["preflight"]["revision"], "required_claims": expected_claims}
    require(completion["policy"] == policy and completion["bindings"] ==
            {**implementation["completion"], "policy_sha256": ARTIFACT.digest(encoded(policy))} and
            completion["coverage"] == {"required_count": 5, "matched_count": 5, "unexpected_count": 0, "observed_count": 5} and
            completion["missing_claims"] == [] and completion["unexpected_claims"] == [] and
            completion["input"] == {"schema": "policy-studio/completion-input/v1", "request_id": "req_" + preflight["context_sha256"][7:],
                "records": [{"claim_id": ob["claim_id"], "status": ob["status"], "evidence_ids": [ob["evidence_id"]]}
                            for ob in producer["observations"]]}, "whole required completion input or bindings differ")
    require(len(completion["steps"]) == 5, "completion erased an intermediate fold")
    for i, step in enumerate(completion["steps"]):
        require(step == {"index": i, "counts_before": ARTIFACT.counts(case["statuses"][:i]), "status": case["statuses"][i],
                        "decision": {**ARTIFACT.counts(case["statuses"][:i+1]), "valid": True, "complete": approved,
                                     "reason": "ACCUMULATED"}}, "ordered cumulative completion decision differs")
    require(completion["summary"] == {**ARTIFACT.counts(case["statuses"]), "valid": True, "complete": approved,
                                         "reason": "ALL_PASS" if approved else "NON_PASS_RESULTS"} and
            completion["readiness"] == {"ready": approved, "reason": "READY" if approved else "NON_PASS_RESULTS",
                "counts_ok": True, "coverage_ok": True, "summary_ok": True, "all_pass_ok": approved}, "whole completion readiness differs")
    effects = {"mutatesTarget": True, "mutatesSession": True, "writesFilesystem": True, "launchesProcess": False,
               "accessesNetwork": False, "changesUiState": False, "mayDiscardData": False,
               "executesForeignCode": False, "mutatesDevice": False, "idempotent": True}
    audit = preflight["audit"]
    require(audit["reads_artifact"] and audit["approval"] == effects and audit["control_plane"] == {**effects, "mutatesTarget": False},
            "actual operation audit differs")
    original_audit = copy.deepcopy(audit)
    original_audit["identity"] = ""
    require(audit["identity"] == ARTIFACT.digest(encoded({"audit": original_audit, "host_sha256": implementation["host_sha256"]})) ==
            implementation["audit_sha256"], "audit source identity differs")
    decision = {"admissible": True, "reason": "WITHIN_EFFECT_BUDGET", "target_ok": True, "session_ok": True,
                "filesystem_ok": True, "process_ok": True, "network_ok": True, "ui_ok": True, "discard_ok": True,
                "foreign_code_ok": True, "device_ok": True, "idempotency_ok": True}
    require(preflight["approval_effects"] == decision == preflight["control_plane_effects"] and
            preflight["admission_facts"] == {"provenance_ok": True, "base_policy_approved": True, "required_count": 5,
                "observed_count": 5, "admissible_evidence_count": 5 if approved else 0, "completion_ready": approved,
                "approval_effect_admissible": True, "control_plane_effect_admissible": True} and
            preflight["decision"] == {"admitted": approved, "reason": case["reason"], "counts_ok": True,
                "provenance_ok": True, "base_policy_ok": True, "evidence_ok": approved, "completion_ok": approved,
                "approval_effect_ok": True, "control_plane_effect_ok": True}, "whole compiled effect or final admission decision differs")
    receipt = out["receipt"]
    copied = copy.deepcopy(receipt)
    copied["id"] = ""
    approved_base = {"approved": True, "reason": "APPROVED", "amount_ok": True, "team_ok": True,
                     "reviewer_ok": True, "self_ok": True, "submitted_ok": True}
    require(receipt["id"] == ARTIFACT.digest(encoded(copied)) and receipt["created_at"] == out["created_at"] and
            receipt["compiler_source_sha"] == ARTIFACT.BASE_PIN and
            receipt["source_sha256"] == ARTIFACT.digest((PROJECT / "internal/policy/approval.gooo").read_bytes()) and
            receipt["generated_sha256"] == ARTIFACT.digest((PROJECT / "internal/policy/generated.txt").read_bytes()) and
            receipt["result"] == {"before": approved_base, "after": approved_base,
                                  "change": {"changed": False, "direction": "UNCHANGED", "reason_changed": False}},
            "whole base receipt source, byte identity or Gooo decision differs")
    require(receipt["input"] == {"request": context["request"]["request"],
                "reviewer": {"key": principal["key"], "team": principal["team"], "active": principal["active"]},
                "before": config["policy"], "after": config["policy"]}, "whole base request/policy/principal facts differ")
    return result, implementation


def main_flow(observer, directory, sources, lost=False):
    directory.mkdir(mode=0o700)
    cases, config = fixture(directory, lost)
    state, token = observer.init(directory / "operator", config, "lost_fixture_init" if lost else "client_fixture_init")
    credential = directory / "operator/private.token"
    process, base, lifecycle = observer.start(state, "lost_response_gate" if lost else "client_gate_first_process")
    prepared, originals = {}, {}
    try:
        view = observer.http(base, token, "GET", "/api/state")
        observer.proof["transport_observations"].append({**view, "case": "lost_initial_state" if lost else "initial_state", "kind": "observer_GET"})
        require(view["status"] == 200 and view["response"]["schema"] == VIEW_SCHEMA and
                len(view["response"]["requests"]) == 2 and all(r["revision"] == 1 and r["status"] == "pending" for r in view["response"]["requests"]),
                "literal initial two-request state differs")
        with LocalFixture(observer, gate=base, token=token) as relay:
            for case in cases:
                if lost and case["case"] != "ready":
                    continue
                name = ("lost_" if lost else "") + case["case"]
                command_file = directory / (name + ".command.json")
                key = "client-proof-" + name
                before = (state / "snapshot.json").read_bytes()
                mark = relay.mark()
                summary = observer.invoke("prepare_" + name, flags("prepare", relay.address, credential, command_file,
                    request=case["request_id"], key=key), 0, "prepared", 200)
                records = relay.since(mark)
                record_transport(observer, "prepare_" + name, records, ["GET"])
                require(before == (state / "snapshot.json").read_bytes(), "prepare mutated the real gate snapshot")
                command = parse(command_file.read_bytes())
                expected = {"request_id": case["request_id"], "expected_revision": 1,
                            "policy_version": view["response"]["policy_version"], "idempotency_key": key}
                require(command == expected and set(command) == COMMAND_FIELDS and
                        stat.S_IMODE(command_file.stat().st_mode) == 0o600 and summary["action"] == "prepare" and
                        summary["server_schema"] == VIEW_SCHEMA and summary["replayed"] is False and
                        summary["outcome_id"] == "" and summary["reason"] == "" and "claim_counts" not in summary,
                        "prepare did not save exact authoritative intent privately")
                prepared[case["case"]] = (command_file, command, command_file.read_bytes())
                observer.proof["prepared_commands"].append({"case": name, "command": command,
                    "command_file_sha256": sha(command_file.read_bytes()), "mode": "0600", "state_unchanged": True,
                    "actual_GET_count": 1, "actual_POST_count": 0})
            if lost:
                file, command, saved = prepared["ready"]
                relay.drop_next_success = True
                mark = relay.mark()
                summary = observer.invoke("lost_response_after_real_commit", flags("submit", relay.address, credential, file), 2, "error", 0)
                records = relay.since(mark)
                record_transport(observer, "lost_response_after_real_commit", records, ["POST"])
                unchanged_POST(records, saved)
                require(records[0]["response_withheld"] and file.read_bytes() == saved and
                        summary["outcome_id"] == "" and summary["replayed"] is False,
                        "lost response was mislabeled successful or changed intent")
                result, implementation = verify_case(sources, cases[0], command, config, records[0])
                require(result["outcome"]["committed"] and not result["replayed"], "lost fixture did not commit through real gate")
                originals["ready"] = result["outcome"]
                mark = relay.mark()
                report = directory / "lost-recovery.report.json"
                summary = observer.invoke("explicit_saved_command_recovery", flags("submit", relay.address, credential, file, report), 0, "approved", 200)
                records = relay.since(mark)
                record_transport(observer, "explicit_saved_command_recovery", records, ["POST"])
                unchanged_POST(records, saved)
                result = report_result(observer, report, records[0], 200)
                require(result == {"replayed": True, "outcome": originals["ready"]} and file.read_bytes() == saved,
                        "explicit recovery did not return original whole committed outcome")
                summary_outcome(summary, result, 200, True)
                observer.proof["runtime_implementation"] = implementation
                observer.proof["lost_response"] = {"real_gate_status": 200, "real_gate_committed": True,
                    "original_replayed": False, "withheld_response": True, "uncertain_client_exit": 2,
                    "automatic_retry_POST_count": 0, "command_bytes_unchanged": True,
                    "explicit_recovery_exit": 0, "explicit_recovery_status": 200,
                    "explicit_recovery_replayed": True, "original_outcome_id": originals["ready"]["id"],
                    "scope": "One real committed local gate response deliberately disconnected before client delivery; not forced power loss or an external exactly-once effect."}
                return

            file, command, saved = prepared["ready"]
            # A different, prepared-before-approval key remains stale after approval.
            stale = directory / "stale.command.json"
            stale_cmd = {**command, "idempotency_key": "client-proof-stale"}
            before = (state / "snapshot.json").read_bytes()
            mark = relay.mark()
            observer.invoke("prepare_command_that_will_be_stale", flags("prepare", relay.address, credential, stale,
                            request=command["request_id"], key="client-proof-stale"), 0, "prepared", 200)
            record_transport(observer, "prepare_command_that_will_be_stale", relay.since(mark), ["GET"])
            stale_saved = stale.read_bytes()
            require(parse(stale_saved) == stale_cmd and stat.S_IMODE(stale.stat().st_mode) == 0o600 and
                    (state / "snapshot.json").read_bytes() == before,
                    "actual stale fixture prepare did not preserve authoritative state and current intent")
            observer.proof["prepared_commands"].append({"case": "will_be_stale", "command": stale_cmd,
                "command_file_sha256": sha(stale_saved), "mode": "0600", "state_unchanged": True,
                "actual_GET_count": 1, "actual_POST_count": 0})
            for case in cases:
                name = case["case"]
                file, command, saved = prepared[name]
                if name == "digest":
                    case["path"].write_bytes(case["observed_raw"])
                report = directory / (name + ".report.json")
                mark = relay.mark()
                summary = observer.invoke("submit_" + name, flags("submit", relay.address, credential, file, report),
                    0 if name == "ready" else 1, "approved" if name == "ready" else "denied", case["status"])
                records = relay.since(mark)
                record_transport(observer, "submit_" + name, records, ["POST"])
                unchanged_POST(records, saved)
                result = report_result(observer, report, records[0], case["status"])
                expected, implementation = verify_case(sources, case, command, config, records[0])
                require(result == expected and file.read_bytes() == saved, "submit changed original prepared bytes")
                summary_outcome(summary, result, case["status"], name == "ready")
                originals[name] = result["outcome"]
                observer.proof["runtime_implementation"] = implementation
                case["path"].write_bytes(b"mutable artifact no longer has the original JSON bytes\n")
                mark = relay.mark()
                repeat = directory / (name + ".repeat.report.json")
                summary = observer.invoke("same_file_retry_" + name, flags("submit", relay.address, credential, file, repeat),
                    0 if name == "ready" else 1, "approved" if name == "ready" else "denied", case["status"])
                records = relay.since(mark)
                record_transport(observer, "same_file_retry_" + name, records, ["POST"])
                unchanged_POST(records, saved)
                result = report_result(observer, repeat, records[0], case["status"])
                require(result == {"replayed": True, "outcome": originals[name]} and file.read_bytes() == saved,
                        "same-file retry did not preserve whole original result")
                summary_outcome(summary, result, case["status"], name == "ready")

            mark = relay.mark()
            summary = observer.invoke("stale_prepared_command", flags("submit", relay.address, credential, stale), 2, "conflict", 409)
            records = relay.since(mark)
            record_transport(observer, "stale_prepared_command", records, ["POST"])
            unchanged_POST(records, stale_saved)
            require(records[0]["response"] == {"error": "conflict"} and stale.read_bytes() == stale_saved,
                    "stale prepared command was silently refreshed")
            rejected_boundaries(observer, directory, state, base, token, credential, relay, prepared)
        after = observer.http(base, token, "GET", "/api/state")
        require([(r["status"], r["revision"]) for r in after["response"]["requests"]] == [("approved", 2), ("pending", 1)],
                "client boundary cases changed final authoritative request states")
        observer.proof["transport_observations"].append({**after, "case": "state_before_client_restart", "kind": "observer_GET"})
    finally:
        observer.stop(process, lifecycle)
    for case in cases:
        case["path"].unlink()
    process, base, lifecycle = observer.start(state, "client_gate_restart_without_artifacts")
    try:
        with LocalFixture(observer, gate=base, token=token) as relay:
            for case in cases:
                name = case["case"]
                file, command, saved = prepared[name]
                report = directory / (name + ".restart.report.json")
                mark = relay.mark()
                summary = observer.invoke("normal_restart_retry_" + name, flags("submit", relay.address, credential, file, report),
                    0 if name == "ready" else 1, "approved" if name == "ready" else "denied", case["status"])
                records = relay.since(mark)
                record_transport(observer, "normal_restart_retry_" + name, records, ["POST"])
                unchanged_POST(records, saved)
                result = report_result(observer, report, records[0], case["status"])
                require(result == {"replayed": True, "outcome": originals[name]} and file.read_bytes() == saved,
                        "normal restart reopened mutable files or changed historical intent")
                summary_outcome(summary, result, case["status"], name == "ready")
    finally:
        observer.stop(process, lifecycle)


def rejected_boundaries(observer, directory, state, base, token, credential, relay, prepared):
    good, command, saved = prepared["ready"]
    before = (state / "snapshot.json").read_bytes()
    invalid_credential = directory / "wrong.private.token"
    invalid = "a" * 64 if token != "a" * 64 else "b" * 64
    observer.tokens.append(invalid)
    private_file(invalid_credential, (invalid + "\n").encode())
    # Authentication failures use the real gate without the relay's own token check.
    unauthorized_report = directory / "unauthorized.report.json"
    summary = observer.invoke("invalid_token_401", flags("submit", base, invalid_credential, good, unauthorized_report), 2, "error", 401)
    raw = unauthorized_report.read_bytes()
    observer.secret_free(raw)
    require(parse(raw) == {"error": "unauthorized"} and stat.S_IMODE(unauthorized_report.stat().st_mode) == 0o600,
            "invalid token was confused with a durable policy denial")
    observer.proof["transport_observations"].append({"case": "invalid_token_401", "kind": "actual_private_response_export",
        "status": 401, "raw_response_body": raw.decode(), "response_sha256": sha(raw), "response": parse(raw)})
    observer.proof["private_report_observations"].append({"path": str(unauthorized_report), "mode": "0600", "bytes": len(raw), "sha256": sha(raw)})

    unknown = directory / "unknown-field.command.json"
    private_file(unknown, encoded({**command, "provider_verified": True}) + b"\n")
    existing_report = directory / "preserve-existing.report.json"
    private_file(existing_report, b"preserve-existing-private-report\n")
    bad_mode = directory / "unsafe.private.token"
    private_file(bad_mode, (token + "\n").encode())
    bad_mode.chmod(0o644)
    linked = directory / "linked.private.token"
    linked.symlink_to(credential)
    fifo = directory / "fifo.private.token"
    os.mkfifo(str(fifo), 0o600)
    no_request = directory / "absent-request.command.json"
    tests = [
        ("unknown_command_field", flags("submit", relay.address, credential, unknown), unknown),
        ("existing_report_preserved", flags("submit", relay.address, credential, good, existing_report), existing_report),
        ("unsafe_token_mode", flags("submit", relay.address, bad_mode, good), good),
        ("symlink_token_rejected", flags("submit", relay.address, linked, good), good),
        ("fifo_token_nonblocking_rejection", flags("submit", relay.address, fifo, good), good),
        ("caller_revision_override", flags("submit", relay.address, credential, good) + ["--expected-revision", "2"], good),
    ]
    for name, args, preserved in tests:
        old = preserved.read_bytes()
        mark = relay.mark()
        observer.invoke(name, args, 2, "error", 0)
        record_transport(observer, name, relay.since(mark), [])
        require(preserved.read_bytes() == old, name + ": existing intent or report was overwritten")
    mark = relay.mark()
    observer.invoke("prepare_absent_request", flags("prepare", relay.address, credential, no_request,
                    request="req-not-configured", key="client-proof-absent"), 2, "error", 200)
    record_transport(observer, "prepare_absent_request", relay.since(mark), ["GET"])
    require(not no_request.exists(), "absent request created an intent file")
    mark = relay.mark()
    observer.invoke("existing_command_preserved", flags("prepare", relay.address, credential, good,
                    request=prepared["digest"][1]["request_id"], key="client-proof-preserve"), 2, "error", 200)
    records = relay.since(mark)
    require([r["method"] for r in records] in ([], ["GET"]), "existing command triggered a POST")
    for record in records:
        observer.proof["transport_observations"].append({**record, "case": "existing_command_preserved", "kind": "actual_gate_response_via_relay"})
    require(good.read_bytes() == saved, "prepare overwrote an existing command")

    with LocalFixture(observer, mode="redirect", location=relay.address) as redirect:
        mark = relay.mark()
        target = directory / "redirected.command.json"
        observer.invoke("redirect_not_followed", flags("prepare", redirect.address, credential, target,
                        request="req-artifact-digest", key="client-proof-redirect"), 2, "error", 302)
        require(len(redirect.records) == 1 and relay.since(mark) == [] and not target.exists(),
                "redirect reached the authoritative gate or created a command")
        observer.proof["transport_observations"].append({**redirect.records[0], "case": "redirect_not_followed", "kind": "non_authority_redirect_fixture"})
    for index, server in enumerate(["http://192.0.2.1:9", "http://localhost:8091", "https://127.0.0.1:8091",
                                    relay.address + "/prefix", relay.address + "?credential=not-a-token", relay.address + "#fragment",
                                    relay.address.replace("http://", "http://user@"), "http://127.0.0.1:0"]):
        mark = relay.mark()
        observer.invoke("server_URL_boundary_" + str(index), flags("submit", server, invalid_credential, good), 2, "error", 0)
        record_transport(observer, "server_URL_boundary_" + str(index), relay.since(mark), [])
    with LocalFixture(observer, mode="proxy") as proxy:
        env = os.environ.copy()
        env.update({"HTTP_PROXY": proxy.address, "HTTPS_PROXY": proxy.address, "ALL_PROXY": proxy.address,
                    "http_proxy": proxy.address, "https_proxy": proxy.address, "all_proxy": proxy.address,
                    "NO_PROXY": "", "no_proxy": ""})
        mark = relay.mark()
        summary = observer.invoke("environment_proxy_ignored", flags("submit", relay.address, credential, good), 0, "approved", 200, env=env)
        records = relay.since(mark)
        record_transport(observer, "environment_proxy_ignored", records, ["POST"])
        unchanged_POST(records, saved)
        require(proxy.records == [], "client used environment proxy for allowed loopback endpoint")
        result = records[0]["response"]
        require(result["replayed"] and result["outcome"]["command"] == command, "proxy fixture changed saved command")
        summary_outcome(summary, result, 200, True)
    require((state / "snapshot.json").read_bytes() == before and good.read_bytes() == saved,
            "rejected client boundaries modified existing authoritative state or prepared command")


def derive_process_counts(observer):
    proof = observer.proof
    proof["actual_client_invocations"] = sum(o["kind"] == "actual_client_process" for o in proof["observations"])
    proof["actual_gate_initializations"] = sum(o["kind"] == "initialization" for o in proof["observations"])
    proof["actual_gate_starts"] = observer.gate_started
    proof["gate_start_attempts"] = observer.gate_start_attempts
    proof["normal_gate_exits"] = sum(p.get("shutdown") == "normal_SIGTERM" and p.get("exit_code") == 0
                                     for p in proof["processes"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-binary", required=True)
    parser.add_argument("--gate-binary", required=True)
    parser.add_argument("--output", "--out", dest="output", required=True)
    args = parser.parse_args()
    client, gate = Path(args.client_binary).resolve(strict=True), Path(args.gate_binary).resolve(strict=True)
    output = Path(args.output).resolve()
    require(not output.exists(), "public proof output must be a new file")
    sources = inventory()
    binaries = {"client": {"path": str(client), "sha256": sha(client.read_bytes())},
                "gate": {"path": str(gate), "sha256": sha(gate.read_bytes())}}
    proof = {"schema": "policy-studio/private-client-process-observation/v1", "passed": False,
        "started_at_utc": utc(), "binaries": binaries, "source_inventory": sources,
        "observer_host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
        "observations": [], "transport_observations": [], "processes": [], "prepared_commands": [],
        "private_report_observations": [], "raw_credentials_recorded": False,
        "credential_hashes_recorded": False, "authorization_headers_recorded": False, "raw_snapshots_recorded": False,
        "scope": "Finite actual prebuilt client and unchanged gate, fresh private synthetic two-request fixtures, loopback HTTP and normal SIGTERM. Client source bytes are inventoried, not a compiler signature. No external target action, forced power loss, remote deployment, native-suite replay, issuer signature, customer or universal safety claim.",
        "literal_expectations": {"prepare": {"exit": 0, "HTTP": 200, "GET": 1, "POST": 0, "state_unchanged": True},
            "approval": {"exit": 0, "HTTP": 200, "statuses": ["pass"] * 5, "reason": "ADMITTED"},
            "denial": {"exit": 1, "HTTP": 403, "statuses": ["fail"] * 5, "reason": "EVIDENCE_REJECTED"},
            "historical_retry": {"whole_original_outcome": True, "replayed": True},
            "uncertainty": {"exit": 2, "automatic_POST_retries": 0, "explicit_recovery_HTTP": 200, "explicit_recovery_replayed": True}}}
    observer = Observer(gate, client, proof)
    failure = None
    try:
        with tempfile.TemporaryDirectory(prefix="gooo-private-client-proof-") as temporary:
            directory = Path(temporary).resolve(strict=True)
            observer.invoke("client_help", ["--help"], 0)
            help_text = proof["observations"][-1]["stdout"] + proof["observations"][-1]["stderr"]
            require(all(word in help_text for word in ["prepare", "submit", "--server", "--token-file", "--command-file"]),
                    "client help omits complete command interface")
            main_flow(observer, directory / "main", sources)
            main_flow(observer, directory / "lost", sources, lost=True)
        require(inventory() == sources and sha(client.read_bytes()) == binaries["client"]["sha256"] and
                sha(gate.read_bytes()) == binaries["gate"]["sha256"], "source or prebuilt binary bytes changed during observation")
        proof["passed"] = True
        derive_process_counts(observer)
        require(proof["normal_gate_exits"] == 3, "actual gate lifecycle count differs")
        proof["local_approved_transitions"] = 2
        proof["external_target_actions"] = 0
        proof["unit_only_boundaries"] = ["Deterministic private-file replacement-race injection and parent/file sync failures belong to client unit tests.",
                                        "Response-size exhaustion and malformed response schemas are separate bounded client tests; this fixture retains only finite synthetic real responses."]
    except Exception as error:
        failure = type(error).__name__ + ": " + str(error)
        proof["passed"] = False
        proof["failure"] = failure
    derive_process_counts(observer)
    proof["finished_at_utc"] = utc()
    ARTIFACT.assert_public(proof)
    raw = json.dumps(proof, ensure_ascii=False, indent=2).encode() + b"\n"
    observer.secret_free(raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"passed": proof["passed"], "output": str(output), "proof_sha256": sha(raw),
                      "actual_client_invocations": proof.get("actual_client_invocations", 0),
                      "actual_gate_initializations": proof["actual_gate_initializations"],
                      "actual_gate_starts": proof["actual_gate_starts"],
                      "gate_start_attempts": proof["gate_start_attempts"],
                      "normal_gate_exits": proof.get("normal_gate_exits", 0)}))
    if failure:
        raise SystemExit("Finite private-client observation failed; inspect the saved safe proof.")


if __name__ == "__main__":
    main()
