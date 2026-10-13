#!/usr/bin/env python3
"""Observe prebuilt comparison and unchanged gate binaries using finite fixtures.

This observer does not build, download, import product code, or obtain expected
answers from observed results. Literal fixture outcomes are declared before any
product process. Every comparison keeps original input bytes, complete private
reports, and safe stdout. Eligible parity fixtures initialize a fresh real gate
for each proposed policy and retain complete first/replay HTTP bodies and state.
Credentials and initialized credential-bearing snapshot bytes are never saved.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROJECT = Path(__file__).resolve().parents[1]
PROOF_SCHEMA = "policy-studio/artifact-impact-process-proof/v1"
REPORT_SCHEMA = "policy-studio/artifact-policy-comparison/v1"
SUMMARY_SCHEMA = "policy-studio/artifact-impact-summary/v1"
MAX_REPORT = 16 << 20
MAX_RESPONSE = 64 << 20
ARTIFACT_RAW = (b'{\n  "schema": "gooo/export-plan/v1",\n  "action": "prepare_export",\n'
                b'  "destination": "internal",\n  "row_limit": 500,\n  "dry_run": true,\n'
                b'  "format": "jsonl"\n}\n')
ARTIFACT_SHA = "sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533"
FIELDS = [{"name": "action", "type": "text"}, {"name": "destination", "type": "text"},
          {"name": "row_limit", "type": "int64"}, {"name": "dry_run", "type": "bool"},
          {"name": "format", "type": "text"}]
CLAIMS = [{"id": "action_equal", "verifier": "field_equals/v1", "field": "action", "expected": "prepare_export"},
          {"id": "destination_equal", "verifier": "field_equals/v1", "field": "destination", "expected": "internal"},
          {"id": "row_limit_equal", "verifier": "field_equals/v1", "field": "row_limit", "expected": "500"},
          {"id": "dry_run_equal", "verifier": "field_equals/v1", "field": "dry_run", "expected": "true"},
          {"id": "format_equal", "verifier": "field_equals/v1", "field": "format", "expected": "jsonl"}]
BUDGET = {"allow_target": True, "allow_session": True, "allow_filesystem": True,
          "allow_process": False, "allow_network": False, "allow_ui": False,
          "allow_discard": False, "allow_foreign_code": False, "allow_device": False,
          "require_idempotent": True}
CONTROL_BUDGET = {**BUDGET, "allow_target": False}
POLICY = {"schema": "policy-studio/artifact-admission-policy/v1", "id": "artifact-impact-destination",
          "revision": 1, "recipe": {"schema": "policy-studio/artifact-recipe/v1", "producer_id": "flat-json/v1",
          "artifact_schema": "gooo/export-plan/v1", "max_bytes": 65536, "fields": FIELDS, "claims": CLAIMS},
          "required_authority": "live-observation", "max_age_seconds": 60,
          "approval_budget": BUDGET, "control_plane_budget": CONTROL_BUDGET}
BASE_CASE = {"schema": "policy-studio/artifact-impact-case/v1",
             "request": {"key": "req-impact-export", "requester": "operator", "team": "platform",
                         "amount": 0, "submitted": True},
             "principal": {"key": "svc-policy-engine", "team": "platform", "active": True,
                           "enabled": True, "can_execute": True},
             "base_rules": {"limit": 1000000, "same_team": True, "active_reviewer": True, "prevent_self": True},
             "artifact": {"path": "/replace-with-your-private-directory/artifact.json",
                          "expected_sha256": ARTIFACT_SHA, "deadline_unix": 4102444800}}
SCOPE = ("Finite actual comparison and fresh unchanged-gate parity observations; proposed principal facts in "
         "comparison are not authenticated state. Comparisons commit no admission and execute no target action. "
         "Parity gates perform only synthetic local state transitions. Unsigned evidence and source hashes provide "
         "consistency, not issuer authentication. No hostile-filesystem, crash-durability or production safety proof.")


def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(value):
    # The received report's original struct field order is preserved. Go's
    # encoding/json additionally escapes HTML and the two JavaScript separators.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for char, escape in [("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                         ("\u2028", "\\u2028"), ("\u2029", "\\u2029")]:
        text = text.replace(char, escape)
    return text.encode("utf-8")


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise AssertionError("duplicate evidence JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def blob(raw, parsed=True):
    result = {"raw_base64": base64.b64encode(raw).decode("ascii"), "sha256": sha(raw), "bytes": len(raw)}
    if parsed:
        result["parsed"] = parse(raw)
    return result


def private_file(path, raw):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def counts(statuses):
    return {"total": len(statuses), **{s: statuses.count(s) for s in ["pass", "fail", "unsupported", "truncated", "unknown"]}}


def expect(statuses, admitted=True, reason="ADMITTED", acquisition="read_success", artifact_reason="ARTIFACT_VERIFIED"):
    return {"statuses": statuses, "counts": counts(statuses), "would_admit": admitted, "reason": reason,
            "acquisition_status": acquisition, "artifact_reason": artifact_reason}


def fixtures():
    """All expected statuses/reasons are literal declarations, before execution."""
    result = []
    def add(name, before=None, after=None, case=None, expected_before=None, expected_after=None,
            direction="unchanged", changed=None, added=None, removed=None, order=False,
            recipe=False, budget=False, approval=False, artifact=None, kind="regular", parity=True):
        result.append({"id": name, "before": copy.deepcopy(before or POLICY), "after": copy.deepcopy(after or POLICY),
            "case": copy.deepcopy(case or BASE_CASE), "artifact": ARTIFACT_RAW if artifact is None else artifact,
            "artifact_kind": kind, "parity": parity,
            "expected": {"exit_code": 0, "before": expected_before or expect(["pass"] * 5),
            "after": expected_after or expect(["pass"] * 5), "direction": direction, "changed": changed or [],
            "added": added or [], "removed": removed or [], "claim_order_changed": order,
            "recipe_configuration_changed": recipe, "approval_budget_changed": budget, "approval_checks_changed": approval}})
    external = copy.deepcopy(POLICY)
    external["revision"] = 2
    external["recipe"]["claims"][1]["expected"] = "external"
    mismatch = expect(["pass", "fail", "pass", "pass", "pass"], False, "EVIDENCE_REJECTED")
    add("destination_new_denial", after=external, expected_after=mismatch, direction="newly_denied",
        changed=["destination_equal"], recipe=True)
    add("destination_access_expansion", before=external, expected_before=mismatch, direction="newly_allowed",
        changed=["destination_equal"], recipe=True)
    metadata = copy.deepcopy(POLICY)
    metadata["id"], metadata["revision"] = "metadata-only-policy", 3
    add("metadata_only", after=metadata)
    wrong_schema = copy.deepcopy(POLICY)
    wrong_schema["recipe"]["artifact_schema"] = "gooo/export-plan/v2"
    add("schema_changed", after=wrong_schema,
        expected_after=expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="ARTIFACT_SCHEMA_MISMATCH"),
        direction="newly_denied", changed=[c["id"] for c in CLAIMS], recipe=True)
    wrong_type = copy.deepcopy(POLICY)
    wrong_type["recipe"]["fields"][2]["type"] = "text"
    add("row_limit_type_changed", after=wrong_type,
        expected_after=expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="ARTIFACT_TYPE_MISMATCH"),
        direction="newly_denied", changed=[c["id"] for c in CLAIMS], recipe=True)
    target = copy.deepcopy(POLICY)
    target["approval_budget"]["allow_target"] = False
    add("approval_target_disallowed", after=target, expected_after=expect(["pass"] * 5, False, "OPERATION_EFFECT_DISALLOWED"),
        direction="newly_denied", budget=True, approval=True)
    network = copy.deepcopy(POLICY)
    network["approval_budget"]["allow_network"] = True
    add("unused_network_budget_changed", after=network, budget=True)
    added = copy.deepcopy(POLICY)
    added["recipe"]["claims"].append({**CLAIMS[1], "id": "destination_recheck"})
    add("claim_added_same_field", after=added, expected_after=expect(["pass"] * 6), added=["destination_recheck"], recipe=True)
    removed = copy.deepcopy(POLICY)
    removed["recipe"]["claims"] = removed["recipe"]["claims"][:-1]
    add("claim_removed", after=removed, expected_after=expect(["pass"] * 4), removed=["format_equal"], recipe=True)
    ordered = copy.deepcopy(POLICY)
    ordered["recipe"]["claims"] = list(reversed(ordered["recipe"]["claims"]))
    add("claims_reordered", after=ordered, order=True)
    one, one_changed = copy.deepcopy(POLICY), copy.deepcopy(POLICY)
    one["recipe"]["claims"] = [copy.deepcopy(CLAIMS[1])]
    one_changed["recipe"]["claims"] = [{**CLAIMS[1], "expected": "external"}]
    add("one_required_claim", before=one, after=one_changed, expected_before=expect(["pass"]),
        expected_after=expect(["fail"], False, "EVIDENCE_REJECTED"), direction="newly_denied",
        changed=["destination_equal"], recipe=True)
    many = copy.deepcopy(POLICY)
    many["recipe"]["claims"] = [{**CLAIMS[1], "id": "destination_%03d" % i} for i in range(256)]
    for failure in [0, 127, 255]:
        other = copy.deepcopy(many)
        other["recipe"]["claims"][failure]["expected"] = "external"
        states = ["pass"] * 256
        states[failure] = "fail"
        add("claims_256_failure_%d" % failure, before=many, after=other,
            expected_before=expect(["pass"] * 256), expected_after=expect(states, False, "EVIDENCE_REJECTED"),
            direction="newly_denied", changed=["destination_%03d" % failure], recipe=True)
    digest = copy.deepcopy(BASE_CASE)
    digest["artifact"]["expected_sha256"] = "sha256:" + "0" * 64
    bad_digest = expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="ARTIFACT_DIGEST_MISMATCH")
    add("trusted_digest_mismatch", case=digest, expected_before=bad_digest, expected_after=bad_digest)
    deadline = copy.deepcopy(BASE_CASE)
    deadline["artifact"]["deadline_unix"] = 1
    expired = expect(["pass"] * 5, False, "EVIDENCE_REJECTED")
    add("deadline_expired", case=deadline, expected_before=expired, expected_after=expired)
    base = copy.deepcopy(BASE_CASE)
    base["request"]["amount"] = 1000001
    denied = expect(["unknown"] * 5, False, "BASE_POLICY_DENIED", "skipped", "ARTIFACT_READ_SKIPPED")
    add("base_over_limit", case=base, expected_before=denied, expected_after=denied)
    for key, name, reason in [("enabled", "proposed_disabled", "PROPOSED_PRINCIPAL_DISABLED"),
                              ("can_execute", "proposed_no_execution", "PROPOSED_EXECUTION_FORBIDDEN")]:
        permission = copy.deepcopy(BASE_CASE)
        permission["principal"][key] = False
        skipped = expect(["unknown"] * 5, False, reason, "skipped", "ARTIFACT_READ_SKIPPED")
        add(name, case=permission, expected_before=skipped, expected_after=skipped)
    for name, kind in [("artifact_missing", "missing"), ("artifact_symlink", "symlink"), ("artifact_fifo", "fifo")]:
        unknown = expect(["unknown"] * 5, False, "EVIDENCE_REJECTED", "read_error", "ARTIFACT_READ_ERROR")
        add(name, kind=kind, expected_before=unknown, expected_after=unknown)
    oversized = expect(["truncated"] * 5, False, "EVIDENCE_REJECTED", "oversized", "ARTIFACT_OVERSIZED")
    add("artifact_oversized", artifact=b"x" * 65537, expected_before=oversized, expected_after=oversized)
    empty_case = copy.deepcopy(BASE_CASE)
    empty_case["artifact"]["expected_sha256"] = sha(b"")
    empty = expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="EMPTY_ARTIFACT")
    add("artifact_empty", case=empty_case, artifact=b"", expected_before=empty, expected_after=empty)
    malformed_raw = b'{"schema":"gooo/export-plan/v1","schema":"gooo/export-plan/v1"}'
    malformed_case = copy.deepcopy(BASE_CASE)
    malformed_case["artifact"]["expected_sha256"] = sha(malformed_raw)
    malformed = expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="INVALID_ARTIFACT_JSON")
    add("artifact_duplicate_key", case=malformed_case, artifact=malformed_raw, expected_before=malformed, expected_after=malformed)
    field_change = copy.deepcopy(POLICY)
    field_change["recipe"]["fields"][4]["name"] = "encoding"
    field_change["recipe"]["claims"][4]["field"] = "encoding"
    add("configured_field_changed", after=field_change,
        expected_after=expect(["fail"] * 5, False, "EVIDENCE_REJECTED", artifact_reason="ARTIFACT_SCHEMA_MISMATCH"),
        direction="newly_denied", changed=[c["id"] for c in CLAIMS], recipe=True)
    # Negative configuration and private-file cases never select expectations
    # from an observed error. Every fixed code is declared explicitly here.
    invalid = [("case_duplicate_key", "CASE_INVALID"), ("case_unknown_field", "CASE_INVALID"),
        ("case_null_principal", "CASE_INVALID"), ("case_trailing_value", "CASE_INVALID"),
        ("case_invalid_surrogate", "CASE_INVALID"), ("case_zero_deadline", "CASE_INVALID"),
        ("before_duplicate_key", "BEFORE_POLICY_INVALID"), ("after_unknown_field", "AFTER_POLICY_INVALID"),
        ("after_null_claims", "AFTER_POLICY_INVALID"), ("after_zero_claims", "AFTER_POLICY_INVALID"),
        ("after_257_claims", "AFTER_POLICY_INVALID"), ("after_duplicate_claim", "AFTER_POLICY_INVALID"),
        ("after_unsupported_verifier", "AFTER_POLICY_INVALID"), ("after_int64_overflow", "AFTER_POLICY_INVALID"),
        ("after_noncanonical_integer", "AFTER_POLICY_INVALID"), ("after_max_bytes_zero", "AFTER_POLICY_INVALID"),
        ("common_max_bytes_changed", "COMMON_CONSTRAINT_MISMATCH"), ("common_authority_changed", "COMMON_CONSTRAINT_MISMATCH"),
        ("common_age_changed", "COMMON_CONSTRAINT_MISMATCH"), ("common_control_budget_changed", "COMMON_CONSTRAINT_MISMATCH"),
        ("control_budget_denies_persistence", "CONTROL_PLANE_BUDGET_INVALID"),
        ("unsafe_case_mode", "CASE_FILE_INVALID"), ("symlink_before", "BEFORE_FILE_INVALID"),
        ("fifo_case", "CASE_FILE_INVALID"), ("case_oversized", "CASE_FILE_INVALID"),
        ("report_existing_preserved", "REPORT_FILE_UNAVAILABLE"), ("report_equals_case", "REPORT_FILE_UNAVAILABLE"),
        ("report_equals_before", "REPORT_FILE_UNAVAILABLE"), ("report_equals_after", "REPORT_FILE_UNAVAILABLE"),
        ("report_equals_missing_artifact", "REPORT_FILE_UNAVAILABLE"),
        ("report_parent_alias_missing_artifact", "REPORT_FILE_UNAVAILABLE"),
        ("report_equals_missing_artifact_ancestor", "REPORT_FILE_UNAVAILABLE"),
        ("report_hardlink_artifact", "REPORT_FILE_UNAVAILABLE")]
    for name, code in invalid:
        result.append({"id": name, "before": copy.deepcopy(POLICY), "after": copy.deepcopy(POLICY),
            "case": copy.deepcopy(BASE_CASE), "artifact": ARTIFACT_RAW, "artifact_kind": "regular", "parity": False,
            "expected": {"exit_code": 2, "code": code, "report_unchanged_or_absent": True}})
    return result


def inventory():
    result = {}
    for root in [PROJECT / "internal", PROJECT / "cmd"]:
        for path in sorted(root.rglob("*")):
            if path.is_file() and (path.suffix in {".go", ".gooo"} or path.name in
                {"generated.txt", "bridge.txt", "generation.json", "compiler-version.txt"}):
                if path.name.endswith("_test.go"):
                    continue
                raw = path.read_bytes()
                result[str(path.relative_to(PROJECT))] = {"sha256": sha(raw), "bytes": len(raw)}
    optional_sum = [PROJECT / "go.sum"] if (PROJECT / "go.sum").is_file() else []
    for path in [PROJECT / "go.mod", *optional_sum, Path(__file__).resolve()]:
        raw = path.read_bytes()
        result[str(path.relative_to(PROJECT))] = {"sha256": sha(raw), "bytes": len(raw)}
    return result


def public_sanitize(value, tokens, key=""):
    """Every save path excludes credentials, even a failed privacy assertion.

    Removed evidence makes the proof failed and visibly incomplete. Retained
    report bytes/hashes are never silently rewritten into an accepted proof.
    This checks current token/digest echoes, raw base64 bodies and ASCII JSON
    Unicode escapes; arbitrary encryption is outside this observation scope.
    """
    redactions = 0
    if isinstance(value, dict):
        clean = {}
        for name, item in value.items():
            checked_name, key_redactions = public_sanitize(name, tokens, "property_name")
            if key_redactions:
                # Remove the whole entry instead of manufacturing a key that
                # might collide with another legitimate evidence property.
                redactions += key_redactions
                continue
            clean[name], number = public_sanitize(item, tokens, name)
            redactions += number
        return clean, redactions
    if isinstance(value, list):
        clean = []
        for item in value:
            selected, number = public_sanitize(item, tokens, key)
            clean.append(selected)
            redactions += number
        return clean, redactions
    if isinstance(value, str):
        candidates = [value.encode("utf-8")]
        if key in {"raw_base64", "artifact_base64", "stdout_base64", "stderr_base64"}:
            try:
                candidates.append(base64.b64decode(value, validate=True))
            except ValueError:
                pass
        candidates.extend(re.sub(rb"\\u00([0-7][0-9a-fA-F])", lambda match: bytes([int(match.group(1), 16)]), raw)
                          for raw in list(candidates))
        forbidden = [needle for token in tokens for needle in
                     [token.encode(), hashlib.sha256(token.encode()).hexdigest().encode()]]
        if any(needle in raw for raw in candidates for needle in forbidden):
            return "[REDACTED_UNSAFE_OBSERVER_RECORD]", 1
    return value, 0


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Observer:
    def __init__(self, impact, gate, proof):
        self.impact, self.gate, self.proof = impact, gate, proof
        self.tokens = []
        self.live = []
        self.failed_assertion = None

    def require(self, okay, message):
        self.proof["counters"]["assertions"] += 1
        if not okay:
            self.failed_assertion = message
            raise AssertionError(message)

    def secret_free(self, raw):
        for token in self.tokens:
            self.require(token.encode() not in raw and hashlib.sha256(token.encode()).hexdigest().encode() not in raw,
                         "synthetic credential or its digest was retained")

    def process(self, argv, counter, timeout=30):
        attempts = {"comparison_calls": "comparison_call_attempts", "gate_initializations": "gate_initialization_attempts"}[counter]
        self.proof["counters"][attempts] += 1
        record = {"argv": list(map(str, argv)), "started_at_utc": utc(), "finished_at_utc": None,
                  "exit_code": None, "stdout": "", "stderr": "", "process_started": False}
        try:
            process = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            record.update({"finished_at_utc": utc(), "process_error": "SPAWN_FAILED"})
            return record
        self.proof["counters"][counter] += 1
        record["process_started"] = True
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate(timeout=5)
            record["process_error"] = "TIMEOUT"
        utf8_valid = True
        try:
            out.decode("utf-8"), err.decode("utf-8")
        except UnicodeDecodeError:
            utf8_valid = False
        record.update({"finished_at_utc": utc(), "exit_code": process.returncode,
                       "stdout": out.decode("utf-8", errors="replace"), "stderr": err.decode("utf-8", errors="replace"),
                       "stdout_base64": base64.b64encode(out).decode(), "stderr_base64": base64.b64encode(err).decode(),
                       "stdout_sha256": sha(out), "stderr_sha256": sha(err), "utf8_valid": utf8_valid})
        # The caller attaches this completed record before any privacy or
        # semantic assertion. A failing check cannot lose an actual execution.
        return record

    def http(self, base, token, method, path, raw=None):
        self.proof["counters"]["http_calls"] += 1
        record = {"method": method, "path": path, "started_at_utc": utc(), "wall_start_unix": time.time()}
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            with opener.open(Request(base + path, data=raw, headers=headers, method=method), timeout=15) as reply:
                status_code, body = reply.status, reply.read(MAX_RESPONSE + 1)
        except HTTPError as reply:
            status_code, body = reply.code, reply.read(MAX_RESPONSE + 1)
        self.secret_free(body)
        record.update({"finished_at_utc": utc(), "wall_finish_unix": time.time(), "status": status_code,
                       "raw_response": blob(body), "response": parse(body)})
        if raw is not None:
            record["raw_command"] = blob(raw)
        self.require(len(body) <= MAX_RESPONSE, "actual gate response exceeded bound")
        return record

    def start(self, state, parity):
        self.proof["counters"]["gate_start_attempts"] += 1
        argv = [str(self.gate), "-state", str(state), "-addr", "127.0.0.1:0"]
        record = {"argv": argv, "started_at_utc": utc(), "stdout": "", "stderr": "", "exit_code": None}
        parity["start"] = record
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.live.append((process, record))
        os.set_blocking(process.stdout.fileno(), False)
        poller = selectors.DefaultSelector()
        poller.register(process.stdout, selectors.EVENT_READ)
        line, deadline = b"", time.monotonic() + 12
        try:
            while b"\n" not in line and len(line) < 4096 and time.monotonic() < deadline:
                if not poller.select(timeout=max(0, deadline - time.monotonic())):
                    break
                part = os.read(process.stdout.fileno(), 4096 - len(line))
                if not part:
                    break
                line += part
        finally:
            poller.close()
            os.set_blocking(process.stdout.fileno(), True)
        record["stdout"] = line.decode("utf-8", errors="replace")
        self.require(b"\n" in line and len(line) < 4096, "fresh gate did not announce one bounded listener line")
        self.secret_free(line)
        match = re.fullmatch(rb"Gooo machine request gate: (http://127\.0\.0\.1:[0-9]+)\n", line)
        self.require(match is not None, "fresh gate announced unexpected listener")
        self.proof["counters"]["gate_started"] += 1
        return process, match.group(1).decode()

    def stop(self, process, parity):
        process.send_signal(signal.SIGTERM)
        try:
            out, err = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            out, err = process.communicate(timeout=5)
        record = parity["start"]
        record.update({"finished_at_utc": utc(), "stdout": record["stdout"] + out.decode(errors="replace"),
                       "stderr": err.decode(errors="replace"), "exit_code": process.returncode})
        self.live = [(p, r) for p, r in self.live if p is not process]
        if process.returncode == 0:
            self.proof["counters"]["gate_normal_exits"] += 1
        self.secret_free(out + err)
        self.require(process.returncode == 0 and not err, "fresh gate failed to stop normally")

    def cleanup(self):
        # A listener readiness or semantic assertion failure still records and
        # stops the already-created actual process; it cannot erase its counts.
        outputs = []
        for process, record in list(self.live):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                out, err = process.communicate(timeout=5)
            record.update({"finished_at_utc": utc(), "stdout": record["stdout"] + out.decode(errors="replace"),
                           "stderr": err.decode(errors="replace"), "exit_code": process.returncode, "failure_cleanup": True})
            if process.returncode == 0:
                self.proof["counters"]["gate_normal_exits"] += 1
            self.live.remove((process, record))
            outputs.append(out + err)
        for raw in outputs:
            self.secret_free(raw)

    def validate_source(self, identity):
        self.require(identity["schema"] == "policy-studio/artifact-impact-source/v1", "simulation source identity schema differs")
        names = ["model.go", "compare.go", "validate.go", "delta.go", "identity.go", "files.go", "files_unix.go", "files_other.go"]
        expected = [{"path": n, "sha256": sha((PROJECT / "internal/artifactimpact" / n).read_bytes())} for n in names]
        self.require(identity["host_sources"] == expected and identity["host_sha256"] == sha(encoded(expected)),
                     "embedded simulation host source bytes differ")
        producer = identity["producer"]
        for key, name in [("model_sha256", "model.go"), ("validation_sha256", "validation.go"),
                          ("verifier_sha256", "verifier.go"), ("reader_sha256", "reader.go"),
                          ("reader_unix_sha256", "reader_unix.go"), ("reader_other_sha256", "reader_other.go"),
                          ("identity_sha256", "identity.go")]:
            self.require(producer[key] == sha((PROJECT / "internal/artifactpreflight" / name).read_bytes()),
                         "producer source bytes differ: " + key)
        self.require(identity["goos"] == platform.system().lower() and identity["goarch"] ==
                     {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine()),
                     "actual binary runtime platform differs")

    def check_report(self, record, fixture):
        report, expected = record["comparison"]["report"]["parsed"], fixture["expected"]
        case, before, after = record["fixtures"]["case"]["parsed"], fixture["before"], fixture["after"]
        self.require(report["schema"] == REPORT_SCHEMA and report["simulation"] is True and
                     report["authenticated_server_state"] is False and report["committed"] is False and
                     report["target_effects_executed"] is False, "comparison falsely represented live admission")
        without_id = copy.deepcopy(report)
        without_id["id"] = ""
        self.require(report["id"] == sha(encoded(without_id)), "complete comparison ID binding differs")
        self.validate_source(report["implementation"])
        self.require(report["audit"]["artifact_read_attempts"] == (0 if expected["before"]["acquisition_status"] == "skipped" else 1),
                     "comparison did not use one eligible opaque acquisition")
        self.require(report["audit"]["input_files_read"] == 3 and report["audit"]["private_report_reserved"] is True and
                     report["audit"]["private_report_write_planned"] is True, "comparison IO audit differs")
        self.require(report["before"]["producer"]["artifact_base64"] == report["after"]["producer"]["artifact_base64"] and
                     report["before"]["producer"]["actual_sha256"] == report["after"]["producer"]["actual_sha256"],
                     "two proposed policies did not evaluate the same acquired bytes")
        for name, policy in [("before", before), ("after", after)]:
            side, exp = report[name], expected[name]
            context = side["context"]
            self.require(context["case"] == case and context["policy"] == policy and context["side"] == name and
                         context["inputs"] == report["inputs"] and context["implementation"] == report["implementation"] and
                         context["domain"] == "policy-studio/artifact-impact-simulation-context/v1", "complete proposed context differs")
            self.require(side["context_sha256"] == sha(encoded(context)), "complete proposed context hash differs")
            for input_name, value in [("case", context["case"]), ("before", before), ("after", after)]:
                self.require(report["inputs"][input_name] == {"raw_sha256": record["fixtures"][input_name]["sha256"],
                    "semantic_sha256": sha(encoded(value))}, "raw and typed input bindings differ")
            version = {"domain": "policy-studio/artifact-impact-simulation-policy/v1", "policy": policy,
                       "case": case, "implementation": report["implementation"]}
            self.require(side["simulation_policy_version"] == sha(encoded(version)), "proposed policy version binding differs")
            producer = side["producer"]
            self.require(producer["identity"] == report["implementation"]["producer"] and
                         producer["recipe_sha256"] == sha(encoded(policy["recipe"])) and
                         producer["context_digest"] == side["context_sha256"] and
                         producer["expected_sha256"] == case["artifact"]["expected_sha256"] and
                         producer["observation_unix"] == report["observation_unix"], "producer whole context/source bindings differ")
            raw = base64.b64decode(producer["artifact_base64"], validate=True)
            self.require(producer["actual_sha256"] == sha(raw) and producer["byte_count"] == len(raw), "retained byte/hash binding differs")
            if exp["acquisition_status"] == "read_success":
                self.require(raw == fixture["artifact"], "successful acquisition retained different original bytes")
            else:
                self.require(raw == b"", "metadata/skipped/failed acquisition claimed nonempty entire bytes")
            self.require(producer["acquisition_status"] == exp["acquisition_status"] and
                         producer["artifact_reason"] == exp["artifact_reason"], "literal acquisition/predicate result differs")
            obs = producer["observations"]
            self.require([o["status"] for o in obs] == exp["statuses"] and
                         [o["claim_id"] for o in obs] == [c["id"] for c in policy["recipe"]["claims"]],
                         "complete ordered producer outcomes differ from literal expectations")
            self.require(side["would_admit"] == exp["would_admit"] and side["reason"] == exp["reason"], "literal admission differs")
            completion = side["completion"]
            self.require({k: completion["summary"][k] for k in exp["counts"]} == exp["counts"] and
                         len(completion["steps"]) == len(exp["statuses"]) and len(side["evidence"]) == len(obs),
                         "full completion/evidence counts differ")
            running = counts([])
            for index, (step, status_value, observation, evidence) in enumerate(zip(completion["steps"], exp["statuses"], obs, side["evidence"])):
                self.require(step["index"] == index and step["counts_before"] == running and step["status"] == status_value,
                             "ordered completion fold input differs")
                running = {**running, "total": running["total"] + 1, status_value: running[status_value] + 1}
                self.require(step["decision"] == {**running, "valid": True, "complete": running["pass"] == running["total"], "reason": "ACCUMULATED"},
                             "ordered completion fold output differs")
                self.require(evidence["claim_id"] == observation["claim_id"] and
                             evidence["facts"]["observed_binding"] == side["context_sha256"] and
                             evidence["facts"]["required_binding"] == side["context_sha256"] and
                             evidence["facts"]["observed_artifact"] == sha(raw) and
                             evidence["facts"]["required_artifact"] == case["artifact"]["expected_sha256"] and
                             evidence["facts"]["observed_policy"] == side["simulation_policy_version"] and
                             evidence["facts"]["required_policy"] == side["simulation_policy_version"] and
                             evidence["facts"]["observed_at_unix"] == report["observation_unix"] and
                             evidence["facts"]["now_unix"] == report["observation_unix"], "complete evidence factual bindings differ")
                self.require(completion["input"]["records"][index] == {"claim_id": observation["claim_id"],
                    "status": observation["status"], "evidence_ids": [observation["evidence_id"]]}, "completion lost exact retained evidence identity")
            self.require(completion["policy"]["required_claims"] == [c["id"] for c in policy["recipe"]["claims"]] and
                         completion["missing_claims"] == [] and completion["unexpected_claims"] == [] and
                         completion["readiness"]["ready"] == (exp["counts"]["pass"] == exp["counts"]["total"]),
                         "required claim coverage/readiness differs")
            self.require(side["proposed_approval"]["budget"] == policy["approval_budget"] and
                         side["proposed_control_plane"]["budget"] == policy["control_plane_budget"], "proposed effect budgets differ")
        self.require(report["before"]["context_sha256"] != report["after"]["context_sha256"], "before/after context domains collapsed")
        delta = report["delta"]
        self.require(delta["direction"] == expected["direction"] and delta["added"] == expected["added"] and
                     delta["removed"] == expected["removed"] and [c["claim_id"] for c in delta["changed"]] == expected["changed"],
                     "literal behavioral delta differs")
        for flag in ["claim_order_changed", "recipe_configuration_changed", "approval_budget_changed", "approval_checks_changed"]:
            self.require(delta[flag] == expected[flag], "literal delta flag differs: " + flag)
        summary = record["comparison"]["summary"]
        wanted = {"schema": SUMMARY_SCHEMA, "status": "compared", "code": "COMPARISON_SAVED", "simulation": True,
                  "report_saved": True, "direction": expected["direction"],
                  "before": {"would_admit": expected["before"]["would_admit"], "reason": expected["before"]["reason"], "counts": expected["before"]["counts"]},
                  "after": {"would_admit": expected["after"]["would_admit"], "reason": expected["after"]["reason"], "counts": expected["after"]["counts"]},
                  "added_claims": len(expected["added"]), "removed_claims": len(expected["removed"]), "changed_claims": len(expected["changed"]),
                  **{flag: expected[flag] for flag in ["claim_order_changed", "recipe_configuration_changed", "approval_budget_changed", "approval_checks_changed"]}}
        self.require(summary == wanted, "entire safe summary differs from full private report/literal expected result")

    def parity(self, directory, record, fixture, name):
        case, policy = record["fixtures"]["case"]["parsed"], fixture[name]
        exp = fixture["expected"][name]
        parity = {"side": name}
        record["parity"].append(parity)
        root = directory / ("gate-" + name)
        root.mkdir(mode=0o700)
        bootstrap = {"schema": "policy-studio/admission-bootstrap/v2", "policy": case["base_rules"],
                     "principals": [{**case["principal"], "token_sha256": ""}], "requests": [case["request"]],
                     "preflight": policy, "artifacts": [{"request_id": case["request"]["key"], **case["artifact"]}]}
        source, state, credential = root / "bootstrap.json", root / "state", root / "private.token"
        raw_bootstrap = encoded(bootstrap)
        private_file(source, raw_bootstrap)
        parity["bootstrap"] = blob(raw_bootstrap)
        parity["initialization"] = self.process([self.gate, "-init", source, "-state", state, "-token-file", credential], "gate_initializations")
        token = credential.read_text().strip() if credential.is_file() else ""
        if token:
            self.tokens.append(token)
        self.secret_free(parity["initialization"]["stdout"].encode() + parity["initialization"]["stderr"].encode())
        self.require(parity["initialization"]["exit_code"] == 0 and not parity["initialization"]["stderr"] and
                     parity["initialization"].get("utf8_valid") is True, "fresh real gate initialization failed")
        self.require(re.fullmatch(r"[0-9a-f]{64}", token) is not None, "fresh synthetic credential missing")
        snapshot_raw = (state / "snapshot.json").read_bytes()
        snapshot = parse(snapshot_raw)
        self.require(token.encode() not in snapshot_raw and snapshot["principals"] ==
                     [{**case["principal"], "token_sha256": hashlib.sha256(token.encode()).hexdigest()}],
                     "private initialized principal does not bind actual fresh credential")
        parity["private_modes"] = {"credential": stat.S_IMODE(credential.stat().st_mode), "state": stat.S_IMODE(state.stat().st_mode),
                                  "snapshot": stat.S_IMODE((state / "snapshot.json").stat().st_mode)}
        self.require(parity["private_modes"] == {"credential": 0o600, "state": 0o700, "snapshot": 0o600}, "gate private storage mode differs")
        parity["credential_binding_checked"] = True
        parity["initialized_public_projection"] = {key: snapshot[key] for key in
            ["schema", "policy", "policy_version", "provenance", "requests", "outcomes", "preflight", "artifacts", "implementation"]}
        self.secret_free(encoded(parity["initialized_public_projection"]))
        command = {"request_id": case["request"]["key"], "expected_revision": 1,
                   "policy_version": snapshot["policy_version"], "idempotency_key": "impact-" + record["id"] + "-" + name}
        raw_command = encoded(command)
        parity["command"] = blob(raw_command)
        process = None
        try:
            process, base = self.start(state, parity)
            parity["state_before"] = self.http(base, token, "GET", "/api/state")
            parity["first_response"] = self.http(base, token, "POST", "/api/admit", raw_command)
            parity["replay_response"] = self.http(base, token, "POST", "/api/admit", raw_command)
            parity["state_after"] = self.http(base, token, "GET", "/api/state")
            first, replay = parity["first_response"], parity["replay_response"]
            if not case["principal"]["enabled"] or not case["principal"]["can_execute"]:
                status_code = 401 if not case["principal"]["enabled"] else 403
                error_code = "unauthorized" if status_code == 401 else "forbidden"
                self.require(first["status"] == replay["status"] == status_code and
                             first["response"] == replay["response"] == {"error": error_code},
                             "permission rejection manufactured a durable admission outcome")
            else:
                status_code = 200 if exp["would_admit"] else 403
                self.require(first["status"] == replay["status"] == status_code, "actual gate admission differs from literal comparison")
                first_result = first["response"] if status_code == 200 else first["response"]["result"]
                replay_result = replay["response"] if status_code == 200 else replay["response"]["result"]
                self.require(first_result["replayed"] is False and replay_result["replayed"] is True and
                             first_result["outcome"] == replay_result["outcome"], "actual gate whole-outcome retry was not exact")
                outcome = first_result["outcome"]
                self.require(outcome["schema"] == "policy-studio/admission-outcome/v2" and outcome["command"] == command and
                             outcome["committed"] == exp["would_admit"] and outcome["prior_revision"] == 1 and
                             outcome["new_revision"] == (2 if exp["would_admit"] else 1), "actual local transition differs")
                if exp["would_admit"]:
                    self.proof["counters"]["local_gate_approvals"] += 1
                else:
                    self.proof["counters"]["durable_gate_denials"] += 1
                actual, proposed = outcome["preflight"], record["comparison"]["report"]["parsed"][name]
                self.require(actual["decision"] == proposed["decision"] and actual["admission_facts"] == proposed["admission_facts"] and
                             actual["approval_effects"] == proposed["proposed_approval"]["decision"] and
                             actual["control_plane_effects"] == proposed["proposed_control_plane"]["decision"], "whole native admission/effect parity differs")
                self.require([o["status"] for o in actual["producer"]["observations"]] == exp["statuses"] and
                             {k: actual["completion"]["summary"][k] for k in exp["counts"]} == exp["counts"], "gate complete predicate/fold parity differs")
                for key in ["artifact_base64", "actual_sha256", "expected_sha256", "acquisition_status", "artifact_reason",
                            "digest_ok", "schema_ok", "types_ok", "byte_count", "observed_size", "recipe_sha256", "identity"]:
                    self.require(actual["producer"][key] == proposed["producer"][key], "gate retained artifact/source parity differs: " + key)
                self.require([e["decision"] for e in actual["evidence"]] == [e["decision"] for e in proposed["evidence"]],
                             "all gate evidence decisions differ from proposed policy")
                before_state = parity["state_before"]["response"]["requests"][0]
                after_state = parity["state_after"]["response"]["requests"][0]
                self.require(before_state == {"request": case["request"], "status": "pending", "revision": 1} and
                             after_state == {"request": case["request"], "status": "approved" if exp["would_admit"] else "pending",
                                             "revision": 2 if exp["would_admit"] else 1}, "actual first/replay gate state parity differs")
            final_snapshot = parse((state / "snapshot.json").read_bytes())
            parity["final_public_projection"] = {key: final_snapshot[key] for key in
                ["schema", "policy", "policy_version", "provenance", "requests", "outcomes", "preflight", "artifacts", "implementation"]}
            self.secret_free(encoded(parity["final_public_projection"]))
            self.require(len(final_snapshot["outcomes"]) == (0 if not case["principal"]["enabled"] or not case["principal"]["can_execute"] else 1),
                         "actual fresh gate retained wrong outcome count")
            self.proof["counters"]["parity_sides_checked"] += 1
        finally:
            if process is not None:
                self.stop(process, parity)


def prepare_fixture(directory, fixture):
    """Mutate only synthetic inputs; preserve originals for full-byte checking."""
    case, before, after = copy.deepcopy(fixture["case"]), copy.deepcopy(fixture["before"]), copy.deepcopy(fixture["after"])
    paths = {name: directory / (name + ".json") for name in ["case", "before", "after", "artifact", "report"]}
    case["artifact"]["path"] = str(paths["artifact"])
    kind = fixture["artifact_kind"]
    if kind == "regular":
        private_file(paths["artifact"], fixture["artifact"])
    elif kind == "symlink":
        target = directory / "artifact-target.json"
        private_file(target, fixture["artifact"])
        paths["artifact"].symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(paths["artifact"], 0o600)
    name = fixture["id"]
    if name == "case_zero_deadline":
        case["artifact"]["deadline_unix"] = 0
    if name == "case_null_principal":
        case["principal"] = None
    if name == "case_unknown_field":
        case["caller_now_unix"] = 1
    if name == "after_unknown_field":
        after["caller_pass"] = True
    if name == "after_null_claims":
        after["recipe"]["claims"] = None
    if name == "after_zero_claims":
        after["recipe"]["claims"] = []
    if name == "after_257_claims":
        after["recipe"]["claims"] = [{**CLAIMS[1], "id": "claim_%03d" % i} for i in range(257)]
    if name == "after_duplicate_claim":
        after["recipe"]["claims"].append(copy.deepcopy(CLAIMS[0]))
    if name == "after_unsupported_verifier":
        after["recipe"]["claims"][0]["verifier"] = "caller-supplied/v1"
    if name == "after_int64_overflow":
        after["recipe"]["claims"][2]["expected"] = "9223372036854775808"
    if name == "after_noncanonical_integer":
        after["recipe"]["claims"][2]["expected"] = "0500"
    if name == "after_max_bytes_zero":
        after["recipe"]["max_bytes"] = 0
    if name == "common_max_bytes_changed":
        after["recipe"]["max_bytes"] = 1024
    if name == "common_authority_changed":
        after["required_authority"] = "unit"
    if name == "common_age_changed":
        after["max_age_seconds"] = 61
    if name == "common_control_budget_changed":
        after["control_plane_budget"]["allow_network"] = True
    if name == "control_budget_denies_persistence":
        before["control_plane_budget"]["allow_filesystem"] = after["control_plane_budget"]["allow_filesystem"] = False
    if name in {"report_equals_missing_artifact", "report_parent_alias_missing_artifact", "report_equals_missing_artifact_ancestor"}:
        paths["artifact"].unlink()
        if name == "report_equals_missing_artifact_ancestor":
            missing = directory / "absent-parent"
            case["artifact"]["path"] = str(missing / "nested" / "artifact.json")
            paths["report"] = missing
        elif name == "report_parent_alias_missing_artifact":
            alias = directory / "parent-alias"
            alias.symlink_to(directory, target_is_directory=True)
            case["artifact"]["path"] = str(alias / "artifact.json")
            paths["report"] = paths["artifact"]
        else:
            paths["report"] = paths["artifact"]
    paths["artifact"] = Path(case["artifact"]["path"])
    fixture["case"], fixture["before"], fixture["after"] = case, before, after
    raw = {"case": encoded(case), "before": encoded(before), "after": encoded(after)}
    if name == "case_duplicate_key":
        raw["case"] = raw["case"].replace(b'{"schema":', b'{"schema":"policy-studio/artifact-impact-case/v1","schema":', 1)
    if name == "before_duplicate_key":
        raw["before"] = raw["before"].replace(b'{"schema":', b'{"schema":"policy-studio/artifact-admission-policy/v1","schema":', 1)
    if name == "case_trailing_value":
        raw["case"] += b" {}"
    if name == "case_invalid_surrogate":
        raw["case"] = raw["case"].replace(b'"operator"', b'"\\ud800"')
    if name == "case_oversized":
        raw["case"] += b" " * (1 << 20)
    for key in ["case", "before", "after"]:
        private_file(paths[key], raw[key])
    if name == "unsafe_case_mode":
        paths["case"].chmod(0o644)
    if name == "symlink_before":
        target = directory / "real-before.json"
        paths["before"].rename(target)
        paths["before"].symlink_to(target)
    if name == "fifo_case":
        paths["case"].unlink()
        os.mkfifo(paths["case"], 0o600)
    if name == "report_existing_preserved":
        private_file(paths["report"], b"private-existing-report-preserved\n")
    if name in {"report_equals_case", "report_equals_before", "report_equals_after"}:
        paths["report"] = paths[name.removeprefix("report_equals_")]
    if name == "report_hardlink_artifact":
        os.link(paths["artifact"], paths["report"])
    return paths, raw


def observed_file(path):
    if not path.exists() and not path.is_symlink():
        return {"exists": False}
    info = path.lstat()
    result = {"exists": True, "mode": stat.S_IMODE(info.st_mode), "kind": "symlink" if stat.S_ISLNK(info.st_mode)
              else "fifo" if stat.S_ISFIFO(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "other"}
    if stat.S_ISREG(info.st_mode):
        raw = path.read_bytes()
        result.update(blob(raw, parsed=False))
    if stat.S_ISLNK(info.st_mode):
        result["symlink_target"] = os.readlink(path)
    return result


def run(impact, gate, proof, observer):
    declared = fixtures()
    proof["literal_fixture_catalog"] = [{"id": f["id"], "expected": f["expected"], "parity": f["parity"]} for f in declared]
    observer.require(sha(ARTIFACT_RAW) == ARTIFACT_SHA, "independent literal artifact hash differs")
    for name, expected in [("case.json", BASE_CASE), ("policy-internal.json", POLICY)]:
        raw = (PROJECT / "examples/artifact-impact" / name).read_bytes()
        observer.require(parse(raw) == expected, "documented input differs from independent literal fixture: " + name)
        proof["documented_inputs"][name] = blob(raw)
    external = copy.deepcopy(POLICY)
    external["revision"] = 2
    external["recipe"]["claims"][1]["expected"] = "external"
    for name, expected in [("policy-external.json", external), ("artifact.json", parse(ARTIFACT_RAW))]:
        raw = (PROJECT / "examples/artifact-impact" / name).read_bytes()
        observer.require(parse(raw) == expected and (name != "artifact.json" or sha(raw) == ARTIFACT_SHA),
                         "documented artifact/policy differs from independent literal fixture: " + name)
        proof["documented_inputs"][name] = blob(raw)
    with tempfile.TemporaryDirectory(prefix="gooo-artifact-impact-") as temp:
        root = Path(temp).resolve()
        root.chmod(0o700)
        proof["fixture_root_mode"] = stat.S_IMODE(root.stat().st_mode)
        for fixture in declared:
            directory = root / fixture["id"]
            directory.mkdir(mode=0o700)
            paths, raw = prepare_fixture(directory, fixture)
            record = {"id": fixture["id"], "literal_expected": fixture["expected"], "fixtures": {}, "parity": []}
            proof["cases"].append(record)
            for name in ["case", "before", "after"]:
                record["fixtures"][name] = blob(raw[name], parsed=fixture["expected"]["exit_code"] == 0)
                record["fixtures"][name]["path"] = str(paths[name])
            record["fixtures"]["artifact"] = {**blob(fixture["artifact"], parsed=False),
                "path": fixture["case"]["artifact"]["path"], "kind": fixture["artifact_kind"]}
            initial = {name: observed_file(paths[name]) for name in paths}
            record["file_observations_before"] = initial
            argv = [impact, "compare", "--case", paths["case"], "--before", paths["before"],
                    "--after", paths["after"], "--report", paths["report"]]
            actual = observer.process(argv, "comparison_calls")
            record["comparison"] = actual
            record["file_observations_after"] = {name: observed_file(paths[name]) for name in paths}
            observer.secret_free(actual["stdout"].encode() + actual["stderr"].encode())
            observer.require(actual["exit_code"] == fixture["expected"]["exit_code"] and not actual["stderr"],
                             fixture["id"] + ": literal exit/stderr differs")
            observer.require(actual.get("utf8_valid") is True, "completed comparator output was not valid UTF-8")
            observer.require(len(actual["stdout"].encode()) < 16 << 10, "terminal summary exceeded fixed bound")
            summary = parse(actual["stdout"])
            actual["summary"] = summary
            observer.require(summary["schema"] == SUMMARY_SCHEMA and summary["simulation"] is True, "summary scope differs")
            observer.require(all(secret not in actual["stdout"] for secret in ["prepare_export", "destination_equal", "jsonl",
                             str(root), "artifact_base64", "svc-policy-engine"]), "terminal summary exposed private input values/path")
            for name in ["case", "before", "after", "artifact"]:
                observer.require(record["file_observations_after"][name] == initial[name], "comparison mutated an input or artifact namespace")
            if fixture["expected"]["exit_code"] == 2:
                observer.require(summary["status"] == "error" and summary["code"] == fixture["expected"]["code"] and
                                 summary["report_saved"] is False, "literal safe configuration/file error differs")
                observer.require(record["file_observations_after"]["report"] == initial["report"], "pre-reservation failure created or changed output")
                proof["counters"]["configuration_failures_checked"] += 1
                continue
            report_raw = paths["report"].read_bytes()
            actual["report"] = {**blob(report_raw), "path": str(paths["report"]), "mode": stat.S_IMODE(paths["report"].stat().st_mode)}
            observer.require(actual["report"]["mode"] == 0o600 and len(report_raw) <= MAX_REPORT and
                             observed_file(paths["report"])["kind"] == "regular", "comparison private report boundary differs")
            observer.check_report(record, fixture)
            proof["counters"]["comparisons_checked"] += 1
            if fixture["parity"]:
                for name in ["before", "after"]:
                    observer.parity(directory, record, fixture, name)
    observer.require(not observer.live and proof["counters"]["gate_started"] == proof["counters"]["gate_normal_exits"],
                     "observer left a gate process running or failed exit unrecorded")
    observer.secret_free(encoded(proof))
    proof["credential_nonretention_checked"] = True
    proof["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impact-binary", type=Path, required=True)
    parser.add_argument("--gate-binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    impact, gate = args.impact_binary.resolve(), args.gate_binary.resolve()
    proof = {"schema": PROOF_SCHEMA, "scope": SCOPE, "started_at_utc": utc(), "finished_at_utc": None, "passed": False,
             "source_files": {}, "binaries": {}, "documented_inputs": {}, "cases": [],
             "counters": {key: 0 for key in ["assertions", "comparison_call_attempts", "comparison_calls", "comparisons_checked", "configuration_failures_checked",
                 "gate_initialization_attempts", "gate_initializations", "gate_start_attempts", "gate_started", "gate_normal_exits", "parity_sides_checked",
                 "http_calls", "local_gate_approvals", "durable_gate_denials"]},
             "external_endpoints_used": False, "compiler_or_builds_invoked": False,
             "credential_plaintext_recorded": False, "initialized_snapshot_raw_recorded": False}
    observer = Observer(impact, gate, proof)
    try:
        proof["source_files"] = inventory()
        for name, path in [("impact", impact), ("gate", gate)]:
            raw = path.read_bytes()
            proof["binaries"][name] = {"path": str(path), "sha256": sha(raw), "bytes": len(raw), "mode": stat.S_IMODE(path.stat().st_mode),
                                        "measurement": "observer read actual binary bytes; downstream CI proof alone is not a new independent byte measurement"}
        run(impact, gate, proof, observer)
    except Exception as error:
        proof["failure"] = {"type": type(error).__name__, "code": "OBSERVER_FAILED",
                            "assertion": observer.failed_assertion}
    finally:
        try:
            observer.cleanup()
        except Exception as error:
            proof["passed"] = False
            proof["cleanup_failure"] = {"type": type(error).__name__, "code": "OBSERVER_CLEANUP_FAILED"}
        try:
            proof["source_files_after"] = inventory()
            proof["binary_measurements_after"] = {}
            for name, path in [("impact", impact), ("gate", gate)]:
                binary_raw = path.read_bytes()
                proof["binary_measurements_after"][name] = {"sha256": sha(binary_raw), "bytes": len(binary_raw),
                                                           "mode": stat.S_IMODE(path.stat().st_mode)}
            unchanged = proof["source_files_after"] == proof["source_files"] and all(
                all(measured[key] == proof["binaries"][name][key] for key in ["sha256", "bytes", "mode"])
                for name, measured in proof["binary_measurements_after"].items())
            proof["sources_and_binaries_unchanged"] = unchanged
            if not unchanged:
                proof["passed"] = False
                proof["binding_failure"] = {"code": "SOURCE_OR_BINARY_BYTES_CHANGED"}
        except Exception as error:
            proof["passed"] = False
            proof["binding_failure"] = {"type": type(error).__name__, "code": "FINAL_BINDINGS_UNAVAILABLE"}
        proof["finished_at_utc"] = utc()
        proof, redactions = public_sanitize(proof, observer.tokens)
        proof["mandatory_public_filter_checked"] = True
        proof["privacy_redactions"] = redactions
        if redactions:
            proof["passed"] = False
            proof["failure"] = {"code": "UNSAFE_OBSERVER_EVIDENCE_REDACTED"}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        raw = json.dumps(proof, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8") + b"\n"
        # Never replace a failed or successful previous execution observation.
        private_file(args.out, raw)
    print(json.dumps({"passed": proof["passed"], "counters": proof["counters"], "proof_sha256": sha(raw)}, separators=(",", ":")))
    return 0 if proof["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
