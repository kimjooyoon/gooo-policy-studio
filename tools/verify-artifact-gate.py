#!/usr/bin/env python3
"""Verify an already-built artifact gate using real files and loopback HTTP.

This script never builds a binary or invokes Gooo. Fresh CLI-generated credentials
stay only in a temporary private directory and outgoing request headers. Raw
credential-bearing snapshots and Authorization headers are never recorded.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import platform
import select
import signal
import stat
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PIN = "83928fa4538245abe33b08549da47f8cbdc50ed2"
BASE_PIN = "be4ef88cca4bc3df1e78ae91c8fe8388413f05c9"
CLAIMS = ["service_verified", "enabled_verified", "revision_verified",
          "region_verified", "replicas_verified"]
GOOD = {"schema": "deployment-artifact/v1", "service": "payments",
        "enabled": True, "revision": 7, "region": "ap-northeast-2", "replicas": 3}
FIELD_NAMES = ["service", "enabled", "revision", "region", "replicas"]
FIELDS = [{"name": "service", "type": "text"}, {"name": "enabled", "type": "bool"},
          {"name": "revision", "type": "int64"}, {"name": "region", "type": "text"},
          {"name": "replicas", "type": "int64"}]
EXPECTED = ["payments", "true", "7", "ap-northeast-2", "3"]
ALL_PASS = ["pass", "pass", "pass", "pass", "pass"]
ALL_FAIL = ["fail", "fail", "fail", "fail", "fail"]
ALL_UNKNOWN = ["unknown", "unknown", "unknown", "unknown", "unknown"]
ALL_TRUNCATED = ["truncated", "truncated", "truncated", "truncated", "truncated"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(raw):
    return "sha256:" + sha(raw)


def counts(statuses):
    return {"total": len(statuses), "pass": statuses.count("pass"),
            "fail": statuses.count("fail"), "unsupported": statuses.count("unsupported"),
            "truncated": statuses.count("truncated"), "unknown": statuses.count("unknown")}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def assert_public(value):
    if isinstance(value, dict):
        require(not {str(key).lower() for key in value}.intersection(
            {"token", "token_sha256", "authorization"}), "credential material appeared in public JSON")
        for item in value.values():
            assert_public(item)
    elif isinstance(value, list):
        for item in value:
            assert_public(item)


def budget(target=True):
    return {"allow_target": target, "allow_session": True, "allow_filesystem": True,
            "allow_process": False, "allow_network": False, "allow_ui": False,
            "allow_discard": False, "allow_foreign_code": False, "allow_device": False,
            "require_idempotent": True}


def bootstrap(directory, cases, target=True):
    request_rows, artifacts = [], []
    for case in cases:
        request_id = "req-artifact-" + case["case"]
        case["request_id"] = request_id
        case["path"] = directory / (case["case"] + ".json")
        case["path"].write_bytes(case["raw"])
        request_rows.append({"key": request_id, "requester": "svc-deployer", "team": "platform",
                             "amount": 750000, "submitted": True})
        artifacts.append({"request_id": request_id, "path": str(case["path"]),
                          "expected_sha256": digest(case["raw"]), "deadline_unix": case["deadline"]})
    return {"schema": "policy-studio/admission-bootstrap/v2",
            "policy": {"limit": 1000000, "same_team": True, "active_reviewer": True, "prevent_self": True},
            "principals": [{"key": "svc-artifact-engine", "team": "platform", "active": True,
                            "enabled": True, "can_execute": True, "token_sha256": ""}],
            "requests": request_rows,
            "preflight": {"schema": "policy-studio/artifact-admission-policy/v1",
                          "id": "artifact-process-proof", "revision": 1,
                          "recipe": {"schema": "policy-studio/artifact-recipe/v1", "producer_id": "flat-json/v1",
                                     "artifact_schema": GOOD["schema"], "max_bytes": 65536, "fields": FIELDS,
                                     "claims": [{"id": claim, "verifier": "field_equals/v1", "field": field,
                                                 "expected": expected}
                                                for claim, field, expected in zip(CLAIMS, FIELD_NAMES, EXPECTED)]},
                          "required_authority": "live-observation", "max_age_seconds": 300,
                          "approval_budget": budget(target), "control_plane_budget": budget(False)},
            "artifacts": artifacts}


def declaration(now):
    cases = [
        {"case": "ready", "statuses": ALL_PASS, "status": 200, "reason": "ADMITTED"},
        {"case": "first", "statuses": ["fail", "pass", "pass", "pass", "pass"], "status": 403, "reason": "EVIDENCE_REJECTED", "field": "service", "value": "billing"},
        {"case": "middle", "statuses": ["pass", "pass", "fail", "pass", "pass"], "status": 403, "reason": "EVIDENCE_REJECTED", "field": "revision", "value": 8},
        {"case": "last", "statuses": ["pass", "pass", "pass", "pass", "fail"], "status": 403, "reason": "EVIDENCE_REJECTED", "field": "replicas", "value": 4},
        {"case": "schema", "statuses": ALL_FAIL, "status": 403, "reason": "EVIDENCE_REJECTED", "field": "schema", "value": "wrong/v1", "schema_ok": False, "types_ok": True},
        {"case": "type", "statuses": ALL_FAIL, "status": 403, "reason": "EVIDENCE_REJECTED", "field": "revision", "value": "7", "schema_ok": True, "types_ok": False},
        {"case": "duplicate", "statuses": ALL_FAIL, "status": 403, "reason": "EVIDENCE_REJECTED", "schema_ok": False, "types_ok": False},
        {"case": "digest", "statuses": ALL_FAIL, "status": 403, "reason": "EVIDENCE_REJECTED", "digest_ok": False},
        {"case": "expired", "statuses": ALL_PASS, "status": 403, "reason": "EVIDENCE_REJECTED", "expired": True},
        {"case": "missing", "statuses": ALL_UNKNOWN, "status": 403, "reason": "EVIDENCE_REJECTED", "digest_ok": False, "schema_ok": False, "types_ok": False, "acquisition": "read_error"},
        {"case": "oversized", "statuses": ALL_TRUNCATED, "status": 403, "reason": "EVIDENCE_REJECTED", "digest_ok": False, "schema_ok": False, "types_ok": False, "acquisition": "oversized"},
        {"case": "concurrent", "statuses": ALL_PASS, "status": 200, "reason": "ADMITTED"},
    ]
    for case in cases:
        artifact = dict(GOOD)
        if "field" in case:
            artifact[case["field"]] = case["value"]
        case["raw"] = encoded(artifact)
        if case["case"] == "duplicate":
            case["raw"] = case["raw"].replace(b'"service":"payments"', b'"service":"payments","service":"billing"')
        if case["case"] == "oversized":
            case["raw"] += b" " * (65537 - len(case["raw"]))
        case["observed_raw"] = b"" if case.get("acquisition") in {"read_error", "oversized"} else case["raw"]
        if case["case"] == "digest":
            case["observed_raw"] = encoded({**GOOD, "service": "changed-after-init"})
        case["deadline"] = now - 30 if case.get("expired") else now + 3600
        case["digest_ok"] = case.get("digest_ok", True)
        case["schema_ok"] = case.get("schema_ok", True)
        case["types_ok"] = case.get("types_ok", True)
        case["acquisition"] = case.get("acquisition", "read_success")
    return cases


class Runner:
    def __init__(self, binary, proof):
        self.binary, self.proof, self.tokens = binary, proof, []

    def secret_free(self, raw):
        for token in self.tokens:
            require(token.encode() not in raw, "a process or response disclosed its private credential")

    def init(self, directory, config, name, accepted=True):
        directory.mkdir(mode=0o700)
        source = directory / "operator-bootstrap.json"
        source.write_bytes(encoded(config))
        state, credential = directory / "state", directory / "private.token"
        began = utc()
        result = subprocess.run([str(self.binary), "-init", str(source), "-state", str(state),
                                 "-token-file", str(credential)], capture_output=True, timeout=20)
        token = credential.read_text().strip() if credential.exists() else None
        if token:
            self.tokens.append(token)
        self.secret_free(result.stdout + result.stderr)
        require((result.returncode == 0) == accepted, name + ": unexpected initialization exit")
        record = {"case": name, "kind": "initialization", "expected_accepted": accepted,
                  "exit_code": result.returncode, "started_at_utc": began, "finished_at_utc": utc(),
                  "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
                  "operator_file_sha256": sha(source.read_bytes()), "state_created": state.exists(),
                  "credential_created": credential.exists()}
        if accepted:
            require(token is not None and len(token) == 64 and all(c in "0123456789abcdef" for c in token), name + ": no valid fresh CLI credential")
            modes = {"credential": stat.S_IMODE(credential.stat().st_mode), "state": stat.S_IMODE(state.stat().st_mode),
                     "snapshot": stat.S_IMODE((state / "snapshot.json").stat().st_mode)}
            require(modes == {"credential": 0o600, "state": 0o700, "snapshot": 0o600}, name + ": private file modes differ")
            self.secret_free((state / "snapshot.json").read_bytes())
            record["private_modes"] = modes
        else:
            require(not state.exists() and not credential.exists(), name + ": rejected configuration wrote state or credential")
        self.proof["observations"].append(record)
        return state, token

    def start(self, state, name):
        began = utc()
        process = subprocess.Popen([str(self.binary), "-state", str(state), "-addr", "127.0.0.1:0"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 15)
            require(ready, name + ": listener did not become ready")
            line = process.stdout.readline().strip()
            self.secret_free(line.encode())
            require(line.startswith("Gooo machine request gate: http://127.0.0.1:"), name + ": listener readiness failed")
            require(process.poll() is None, name + ": listener exited before verification")
            address = line.split(": ", 1)[1]
            parsed = urlsplit(address)
            require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None and
                    not parsed.username and not parsed.password and not parsed.path and not parsed.query and not parsed.fragment,
                    "listener address must be a literal loopback URL")
            return process, address, {"case": name, "started_at_utc": began, "readiness_stdout": line}
        except BaseException:
            process.kill()
            process.communicate()
            raise

    def stop(self, process, record):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise RuntimeError("normal SIGTERM shutdown timed out")
        self.secret_free((stdout + stderr).encode())
        record.update({"kind": "process_lifecycle", "shutdown": "normal_SIGTERM", "exit_code": process.returncode,
                       "stdout_after_readiness": stdout, "stderr": stderr, "finished_at_utc": utc()})
        self.proof["processes"].append(record)
        require(process.returncode == 0, record["case"] + ": process did not stop normally")

    def call(self, base, token, method, path, body=None, authenticated=True, raw=None):
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = "Bearer " + token
        data = raw if raw is not None else (None if body is None else encoded(body))
        started, wall_start = utc(), time.time()
        request = Request(base + path, data=data, headers=headers, method=method)
        client = build_opener(ProxyHandler({}), NoRedirect())
        try:
            with client.open(request, timeout=15) as response:
                status, payload = response.status, response.read(4 * 1024 * 1024 + 1)
        except HTTPError as error:
            status, payload = error.code, error.read(4 * 1024 * 1024 + 1)
        require(len(payload) <= 4 * 1024 * 1024, "response exceeded the observer's byte bound")
        self.secret_free(payload)
        parsed = json.loads(payload)
        assert_public(parsed)
        return {"status": status, "method": method, "path": path, "started_at_utc": started,
                "finished_at_utc": utc(), "wall_start_unix": wall_start, "wall_finish_unix": time.time(),
                "response_sha256": sha(payload), "raw_response_body": payload.decode("utf-8"), "response": parsed}

    def record_call(self, case, expected, response, command=None):
        require(response["status"] == expected, case + ": unexpected HTTP status")
        response.update({"case": case, "kind": "loopback_HTTP", "expected_status": expected})
        if command is not None:
            response["command"] = command
        self.proof["observations"].append(response)
        return response["response"]


def source_inventory(project):
    paths = ["tools/verify-artifact-gate.py", "cmd/policy-gate/main.go"]
    for package in ["admission", "artifactpreflight", "jsoninput", "gatehttp", "machinerules", "completion", "policy"]:
        for path in sorted((project / "internal" / package).rglob("*")):
            if path.is_file() and not path.name.endswith("_test.go"):
                paths.append(str(path.relative_to(project)))
    return {path: {"sha256": sha((project / path).read_bytes()), "bytes": (project / path).stat().st_size}
            for path in paths}


def source_group(project, domain, package, names):
    return digest(encoded({"domain": domain, "files": {name: sha((project / "internal" / package / name).read_bytes())
                                                        for name in sorted(names)}}))


def verify_provenance(project, preflight, inventory):
    implementation = preflight["context"]["implementation"]
    require(implementation["schema"] == "policy-studio/artifact-admission-code/v1" and
            implementation["go_version"] == "go1.27.2", "runtime provenance identity differs")
    machine = implementation["machine"]
    generation = json.loads((project / "internal/machinerules/generation.json").read_bytes())
    require(machine["compiler_source_sha"] == PIN and generation["compiler"]["compiler_source_sha"] == PIN,
            "machine compiler pin differs")
    require(machine["generation_sha256"] == digest((project / "internal/machinerules/generation.json").read_bytes()),
            "machine generation byte binding differs")
    require({row["path"]: row["sha256"] for row in machine["sources"]} == generation["sources"], "machine source roster differs")
    for row in machine["sources"]:
        require(row["path"] in inventory or (project / row["path"]).is_file(), "unknown machine source path")
        require(row["sha256"] == digest((project / row["path"]).read_bytes()), "machine source binding differs")
    require(len(machine["projections"]) == 3, "machine projection count differs")
    for projection in machine["projections"]:
        name = projection["name"]
        require(name in {"evidence", "effects", "final"}, "unknown machine projection")
        for key, filename in [("source_sha256", "source.gooo"), ("generated_sha256", "generated.txt"), ("bridge_sha256", "bridge.txt")]:
            require(projection[key] == digest((project / "internal/machinerules" / name / filename).read_bytes()), "compiled projection byte binding differs")
    json_identity = source_group(project, "policy-studio/strict-json-source/v1", "jsoninput", ["strict.go", "provenance.go"])
    require(implementation["decoder_sha256"] == json_identity, "shared strict decoder source differs")
    host_identity = source_group(project, "policy-studio/admission-host-source/v2", "admission",
                                 ["model.go", "store.go", "validate.go", "preflight.go", "preflight_provenance.go", "lock_unix.go", "lock_other.go"])
    require(implementation["host_sha256"] == host_identity, "admission host source differs")
    producer = implementation["producer"]
    require(producer == preflight["producer"]["identity"] and producer["schema"] == "policy-studio/artifact-producer-source/v2" and producer["producer_id"] == "flat-json/v2" and
            producer["verifier_id"] == "artifact-verifier-registry/v2" and producer["json_input_sha256"] == json_identity,
            "producer registry, decoder or context identity differs")
    spec = importlib.util.spec_from_file_location("artifact_numeric_source", Path(__file__).with_name("artifact_numeric_source.py"))
    numeric_source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(numeric_source)
    names = ["source.gooo", "rules_generated.go", "generated.txt", "bridge.go", "bridge.txt", "model.go", "bindings.go", "generator.txt", "generation.json", "compiler-version.txt"]
    numeric_sources = {"internal/artifactnumeric/" + name: (project / "internal/artifactnumeric" / name).read_bytes() for name in names}
    numeric_sources["cmd/generate-artifact-bounds/main.go"] = (project / "cmd/generate-artifact-bounds/main.go").read_bytes()
    require(producer["numeric_bindings"] == numeric_source.expected_numeric_bindings(numeric_sources, json_identity), "numeric implementation bytes differ")
    for key, filename in [("model_sha256", "model.go"), ("validation_sha256", "validation.go"), ("verifier_sha256", "verifier.go"),
                          ("reader_sha256", "reader.go"), ("reader_unix_sha256", "reader_unix.go"),
                          ("reader_other_sha256", "reader_other.go"), ("identity_sha256", "identity.go")]:
        require(producer[key] == digest((project / "internal/artifactpreflight" / filename).read_bytes()), "producer implementation bytes differ")
    for key, filename in [("source_sha256", "source.gooo"), ("generated_sha256", "generated.txt"),
                          ("bridge_sha256", "bridge.txt"), ("generation_sha256", "generation.json")]:
        require(implementation["completion"][key] == digest((project / "internal/completion" / filename).read_bytes()), "completion implementation bytes differ")
    require(implementation["completion"]["compiler_source_sha"] == PIN, "completion compiler pin differs")
    return implementation


def verify_outcome(project, inventory, case, command, config, http, target=True):
    payload = http["response"]
    result = payload if http["status"] == 200 else payload["result"]
    outcome = result["outcome"]
    approved = case["status"] == 200
    require(not result["replayed"] and outcome["schema"] == "policy-studio/admission-outcome/v2" and
            outcome["committed"] == approved and outcome["command"] == command and outcome["prior_revision"] == 1 and
            outcome["new_revision"] == (2 if approved else 1), case["case"] + ": outcome transition differs")
    preflight = outcome["preflight"]
    producer = preflight["producer"]
    require(preflight["schema"] == "policy-studio/artifact-admission-report/v1" and
            producer["schema"] == "policy-studio/artifact-preflight/v2" and producer["producer_id"] == "flat-json/v1", "v2 report schema differs")
    require([o["claim_id"] for o in producer["observations"]] == CLAIMS and
            [o["status"] for o in producer["observations"]] == case["statuses"], case["case"] + ": literal ordered claim expectations differ")
    require((producer["digest_ok"], producer["schema_ok"], producer["types_ok"]) ==
            (case["digest_ok"], case["schema_ok"], case["types_ok"]), case["case"] + ": mandatory artifact guards differ")
    require(producer["acquisition_status"] == case["acquisition"] and
            base64.b64decode(producer["artifact_base64"], validate=True) == case["observed_raw"] and
            producer["actual_sha256"] == digest(case["observed_raw"]) and
            producer["byte_count"] == len(case["observed_raw"]), case["case"] + ": retained actual bytes differ")
    requirement = next(a for a in config["artifacts"] if a["request_id"] == case["request_id"])
    require(producer["expected_sha256"] == requirement["expected_sha256"], "operator digest was replaced")
    require(producer["recipe_sha256"] == digest(encoded(config["preflight"]["recipe"])), "operator recipe binding differs")
    global_reasons = {"schema": "ARTIFACT_SCHEMA_MISMATCH", "type": "ARTIFACT_TYPE_MISMATCH", "duplicate": "INVALID_ARTIFACT_JSON",
                      "digest": "ARTIFACT_DIGEST_MISMATCH", "missing": "ARTIFACT_READ_ERROR", "oversized": "ARTIFACT_OVERSIZED"}
    require(producer["artifact_reason"] == global_reasons.get(case["case"], "ARTIFACT_VERIFIED"), "literal mandatory artifact reason differs")
    actual = {} if case["case"] in {"duplicate", "missing", "oversized"} else json.loads(case["observed_raw"])
    for i, observation in enumerate(producer["observations"]):
        value = actual.get(FIELD_NAMES[i])
        expected_actual = ""
        if FIELDS[i]["type"] == "text" and isinstance(value, str): expected_actual = value
        if FIELDS[i]["type"] == "bool" and isinstance(value, bool): expected_actual = "true" if value else "false"
        if FIELDS[i]["type"] == "int64" and isinstance(value, int) and not isinstance(value, bool): expected_actual = str(value)
        reason = ("FIELD_EQUALS" if case["statuses"][i] == "pass" else "FIELD_MISMATCH") if producer["artifact_reason"] == "ARTIFACT_VERIFIED" else producer["artifact_reason"]
        require((observation["verifier"], observation["field"], observation["expected"], observation["actual"], observation["reason"]) ==
                ("field_equals/v1", FIELD_NAMES[i], EXPECTED[i], expected_actual, reason), "literal field predicate result differs")
        require(len(observation["evidence_id"]) == 67 and observation["evidence_id"].startswith("ev_") and
                all(c in "0123456789abcdef" for c in observation["evidence_id"][3:]), "claim content identifier is not canonical")
    context = preflight["context"]
    require(context["command"] == command and context["artifact"] == requirement and
            context["principal"] == {"key": "svc-artifact-engine", "team": "platform", "active": True, "enabled": True, "can_execute": True} and
            context["request"] == {"request": next(r for r in config["requests"] if r["key"] == case["request_id"]), "status": "pending", "revision": 1}, "authoritative context differs")
    require(preflight["context_sha256"] == digest(encoded(context)) == producer["context_digest"], "context byte binding differs")
    require(int(http["wall_start_unix"]) - 1 <= producer["observation_unix"] <= int(http["wall_finish_unix"]) + 1 and
            producer["observation_unix"] <= preflight["decision_unix"] <= int(http["wall_finish_unix"]) + 1,
            "observed real host timestamps differ")
    implementation = verify_provenance(project, preflight, inventory)
    evidence = preflight["evidence"]
    require([e["claim_id"] for e in evidence] == CLAIMS, "evidence admission omitted or reordered claims")
    admissible = 0
    for e, status in zip(evidence, case["statuses"]):
        facts, decision = e["facts"], e["decision"]
        passing = status == "pass" and not case.get("expired", False)
        reason = "DEADLINE_EXPIRED" if status == "pass" and case.get("expired") else ("ADMISSIBLE" if status == "pass" else "EVIDENCE_INCOMPLETE")
        require(facts == {"actual_authority": "live-observation", "required_authority": "live-observation", "status": status,
                          "confidence": "observed", "provider_verified": True, "observed_binding": producer["context_digest"],
                          "required_binding": preflight["context_sha256"], "observed_artifact": producer["actual_sha256"],
                          "required_artifact": requirement["expected_sha256"], "observed_policy": command["policy_version"],
                          "required_policy": command["policy_version"], "observed_at_unix": producer["observation_unix"],
                          "now_unix": preflight["decision_unix"], "max_age_seconds": 300, "expires_at_unix": requirement["deadline_unix"]},
                "evidence facts differ from trusted actual observations")
        require(decision == {"admissible": passing, "reason": reason, "provider_ok": True,
                             "evidence_ok": status == "pass", "authority_ok": True, "binding_ok": True,
                             "artifact_ok": producer["actual_sha256"] == requirement["expected_sha256"], "policy_ok": True,
                             "freshness_ok": True, "deadline_ok": not case.get("expired", False)},
                case["case"] + ": literal full evidence decision differs")
        admissible += int(passing)
    complete = all(status == "pass" for status in case["statuses"])
    completion = preflight["completion"]
    completion_policy = {"schema": "policy-studio/completion-policy/v1", "policy_id": "artifact-process-proof",
                         "revision": 1, "required_claims": CLAIMS}
    require(completion["policy"] == completion_policy and completion["bindings"] ==
            {**implementation["completion"], "policy_sha256": digest(encoded(completion_policy))}, "separate required-claim policy or completion bindings differ")
    require(completion["coverage"] == {"required_count": 5, "matched_count": 5, "unexpected_count": 0, "observed_count": 5} and
            completion["missing_claims"] == [] and completion["unexpected_claims"] == [], "whole required claim coverage differs")
    require(completion["summary"] == {**counts(case["statuses"]), "valid": True, "complete": complete,
                                      "reason": "ALL_PASS" if complete else "NON_PASS_RESULTS"} and
            completion["readiness"] == {"ready": complete, "reason": "READY" if complete else "NON_PASS_RESULTS",
                                        "counts_ok": True, "coverage_ok": True, "summary_ok": True, "all_pass_ok": complete},
            "literal completion counters or readiness differ")
    require(completion["input"] == {"schema": "policy-studio/completion-input/v1", "request_id": "req_" + preflight["context_sha256"][7:],
                                    "records": [{"claim_id": o["claim_id"], "status": o["status"], "evidence_ids": [o["evidence_id"]]}
                                                for o in producer["observations"]]}, "completion facts differ from every ordered producer observation")
    require(len(completion["steps"]) == 5, "completion erased intermediate steps")
    for i, step in enumerate(completion["steps"]):
        require(step == {"index": i, "counts_before": counts(case["statuses"][:i]), "status": case["statuses"][i],
                         "decision": {**counts(case["statuses"][:i+1]), "valid": True,
                                      "complete": all(s == "pass" for s in case["statuses"][:i+1]), "reason": "ACCUMULATED"}},
                "literal intermediate completion step differs")
    approval_effects = {"mutatesTarget": True, "mutatesSession": True, "writesFilesystem": True, "launchesProcess": False,
                        "accessesNetwork": False, "changesUiState": False, "mayDiscardData": False,
                        "executesForeignCode": False, "mutatesDevice": False, "idempotent": True}
    require(preflight["audit"]["reads_artifact"] and preflight["audit"]["approval"] == approval_effects and
            preflight["audit"]["control_plane"] == {**approval_effects, "mutatesTarget": False}, "actual operation audit differs")
    effect_flags = {"target_ok": True, "session_ok": True, "filesystem_ok": True, "process_ok": True, "network_ok": True,
                    "ui_ok": True, "discard_ok": True, "foreign_code_ok": True, "device_ok": True, "idempotency_ok": True}
    require(preflight["approval_effects"] == {"admissible": target, "reason": "WITHIN_EFFECT_BUDGET" if target else "TARGET_MUTATION_DISALLOWED",
                                             **effect_flags, "target_ok": target} and
            preflight["control_plane_effects"] == {"admissible": True, "reason": "WITHIN_EFFECT_BUDGET", **effect_flags},
            "literal full effect-budget decisions differ")
    require(preflight["admission_facts"] == {"provenance_ok": True, "base_policy_approved": True, "required_count": 5,
                                             "observed_count": 5, "admissible_evidence_count": admissible, "completion_ready": complete,
                                             "approval_effect_admissible": target, "control_plane_effect_admissible": True} and
            preflight["decision"] == {"admitted": approved, "reason": case["reason"], "counts_ok": True,
                                       "provenance_ok": True, "base_policy_ok": True, "evidence_ok": admissible == 5,
                                       "completion_ok": complete, "approval_effect_ok": target, "control_plane_effect_ok": True},
            case["case"] + ": literal full final compiled admission differs")
    receipt = outcome["receipt"]
    require(receipt["compiler_source_sha"] == BASE_PIN and receipt["source_sha256"] == digest((project / "internal/policy/approval.gooo").read_bytes()) and
            receipt["generated_sha256"] == digest((project / "internal/policy/generated.txt").read_bytes()) and receipt["result"]["after"]["approved"],
            "base policy receipt differs")
    return result, implementation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", "--out", dest="output", required=True)
    args = parser.parse_args()
    binary, project = Path(args.binary).resolve(strict=True), Path(__file__).resolve().parents[1]
    binary_sha, inventory = sha(binary.read_bytes()), source_inventory(project)
    started = utc()
    proof = {"schema": "policy-studio/artifact-gate-process-observation/v1", "passed": False,
             "started_at_utc": started, "binary_sha256": binary_sha, "source_inventory": inventory,
             "observer_host": {"system": platform.system(), "machine": platform.machine(), "python": platform.python_version()},
             "compiler_build_identities": {name: json.loads((project / path).read_bytes())["compiler"] for name, path in
                                          [("base", "internal/policy/generation.json"), ("machine", "internal/machinerules/generation.json"),
                                           ("completion", "internal/completion/generation.json")]},
             "observations": [], "processes": [], "raw_credentials_recorded": False,
             "authorization_headers_recorded": False, "raw_credential_snapshots_recorded": False,
             "scope": "Finite independent literal expectations against one actual prebuilt native gate with synthetic operator state, real files and loopback HTTP. Normal SIGTERM/restart only. No forced wall clock, crash/fault injection, signed issuer authentication, external target action, customer or universal safety claim."}
    runner = Runner(binary, proof)
    with tempfile.TemporaryDirectory(prefix="gooo-artifact-gate-proof-") as temporary:
        directory = Path(temporary).resolve(strict=True)
        cases = declaration(int(time.time()))
        proof["literal_case_expectations"] = [{key: value for key, value in case.items() if key not in {"raw", "observed_raw"}}
                                              for case in cases]
        main_dir = directory / "main"
        main_dir.mkdir(mode=0o700)
        config = bootstrap(main_dir, cases)
        state, token = runner.init(main_dir / "operator", config, "valid_v2_configuration")
        for case in cases:
            if case["case"] == "digest": case["path"].write_bytes(case["observed_raw"])
            if case["case"] == "missing": case["path"].unlink()
        command_for = lambda case, key: {"request_id": case["request_id"], "expected_revision": 1,
                                        "policy_version": version, "idempotency_key": key}
        saved_results, commands = {}, {}
        process, base, lifecycle = runner.start(state, "main_first_process")
        try:
            runner.record_call("missing_credential_state", 401, runner.call(base, token, "GET", "/api/state", authenticated=False))
            view = runner.record_call("initial_authoritative_state", 200, runner.call(base, token, "GET", "/api/state"))
            require(view["schema"] == "policy-studio/admission-view/v2" and all(r["status"] == "pending" and r["revision"] == 1 for r in view["requests"]), "initial v2 state differs")
            version = view["policy_version"]
            ready = cases[0]
            command = command_for(ready, "proof-ready")
            runner.record_call("missing_credential_admission", 401, runner.call(base, token, "POST", "/api/admit", command, authenticated=False), command)
            stale = {**command, "policy_version": "sha256:" + "0" * 64}
            runner.record_call("stale_policy", 409, runner.call(base, token, "POST", "/api/admit", stale), stale)
            for name, injected in [("pass", {"status": "pass"}), ("provider", {"provider_verified": True}),
                                   ("effects", {"effects": {"mutatesTarget": False}}), ("clock", {"now_unix": int(time.time())}),
                                   ("path", {"artifact_path": str(ready["path"])}), ("policy", {"preflight": config["preflight"]})]:
                body = {**command, **injected}
                runner.record_call("caller_" + name + "_override", 400, runner.call(base, token, "POST", "/api/admit", body), body)
            duplicate = encoded(command).replace(b'"request_id":', b'"request_id":"duplicate","request_id":', 1)
            runner.record_call("duplicate_command_key", 400, runner.call(base, token, "POST", "/api/admit", raw=duplicate))
            unchanged = runner.record_call("override_attempts_preserve_state", 200, runner.call(base, token, "GET", "/api/state"))
            require(unchanged == view, "invalid caller input changed state")
            for case in cases[:-1]:
                command = command_for(case, "proof-" + case["case"])
                http = runner.call(base, token, "POST", "/api/admit", command)
                result, implementation = verify_outcome(project, inventory, case, command, config, http)
                runner.record_call("actual_" + case["case"], case["status"], http, command)
                commands[case["case"]], saved_results[case["case"]] = command, result
                proof["runtime_implementation"] = implementation
            ready["path"].write_bytes(encoded({**GOOD, "service": "changed-after-commit"}))
            retry = runner.record_call("exact_retry_after_artifact_change", 200,
                                       runner.call(base, token, "POST", "/api/admit", commands["ready"]), commands["ready"])
            require(retry["replayed"] and retry["outcome"] == saved_results["ready"]["outcome"], "exact retry selected changed artifact")
            changed = {**commands["ready"], "expected_revision": 2}
            runner.record_call("same_key_different_command", 409, runner.call(base, token, "POST", "/api/admit", changed), changed)
            concurrent = cases[-1]
            barrier = threading.Barrier(2)
            race_commands = [command_for(concurrent, "proof-concurrent-a"), command_for(concurrent, "proof-concurrent-b")]
            def race(command):
                barrier.wait(timeout=10)
                return runner.call(base, token, "POST", "/api/admit", command)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(race, command) for command in race_commands]
                replies = [future.result(timeout=25) for future in futures]
            require(sorted(reply["status"] for reply in replies) == [200, 409], "concurrent keys did not produce one transition and one conflict")
            proof["concurrent_oracle"] = {"expected_status_multiset": [200, 409],
                                          "actual_status_multiset": sorted(reply["status"] for reply in replies),
                                          "request_id": concurrent["request_id"], "distinct_keys": True}
            for command, http in zip(race_commands, replies):
                runner.record_call("concurrent_distinct_key", http["status"], http, command)
                if http["status"] == 200:
                    result, _ = verify_outcome(project, inventory, concurrent, command, config, http)
                    saved_results["concurrent"], commands["concurrent"] = result, command
            before_restart = runner.record_call("authoritative_state_before_restart", 200, runner.call(base, token, "GET", "/api/state"))
        finally:
            runner.stop(process, lifecycle)
        for case in cases:
            if case["path"].exists(): case["path"].unlink()
        require(all(not case["path"].exists() for case in cases), "artifact removal before historical replay failed")
        process, base, lifecycle = runner.start(state, "main_restart_without_artifact_files")
        try:
            for case in cases:
                body = runner.record_call("historical_retry_without_file_" + case["case"], case["status"],
                                          runner.call(base, token, "POST", "/api/admit", commands[case["case"]]), commands[case["case"]])
                result = body if case["status"] == 200 else body["result"]
                require(result["replayed"] and result["outcome"] == saved_results[case["case"]]["outcome"], "restart changed committed historical outcome")
            final = runner.record_call("authoritative_state_after_restart", 200, runner.call(base, token, "GET", "/api/state"))
            require(final == before_restart, "restart changed authoritative state")
            states = {row["request"]["key"]: [row["status"], row["revision"]] for row in final["requests"]}
            expected_states = {case["request_id"]: ["approved", 2] if case["status"] == 200 else ["pending", 1] for case in cases}
            require(states == expected_states, "final authoritative transitions differ")
            proof["final_request_states"] = states
            snapshot = (state / "snapshot.json").read_bytes()
            runner.secret_free(snapshot)
            proof["final_snapshot_metadata"] = {"sha256": sha(snapshot), "bytes": len(snapshot), "raw_snapshot_recorded": False}
        finally:
            runner.stop(process, lifecycle)

        for name, key, value in [("control_plane_budget_rejection", "control_plane_budget", {**budget(False), "allow_filesystem": False}),
                                 ("unknown_producer_rejection", "recipe", {**config["preflight"]["recipe"], "producer_id": "caller-pass/v1"})]:
            rejected = copy.deepcopy(config)
            rejected["preflight"][key] = value
            runner.init(directory / name, rejected, name, accepted=False)
        denial_dir = directory / "target_budget"
        denial_dir.mkdir(mode=0o700)
        denied_case = declaration(int(time.time()))[0]
        denied_case["case"], denied_case["status"], denied_case["reason"] = "target-budget", 403, "OPERATION_EFFECT_DISALLOWED"
        denial_config = bootstrap(denial_dir, [denied_case], target=False)
        denial_state, denial_token = runner.init(denial_dir / "operator", denial_config, "approval_target_budget_configuration")
        process, base, lifecycle = runner.start(denial_state, "target_budget_first_process")
        try:
            view = runner.record_call("target_budget_initial_state", 200, runner.call(base, denial_token, "GET", "/api/state"))
            denial_command = {"request_id": denied_case["request_id"], "expected_revision": 1,
                              "policy_version": view["policy_version"], "idempotency_key": "proof-target-deny"}
            http = runner.call(base, denial_token, "POST", "/api/admit", denial_command)
            denied_result, _ = verify_outcome(project, inventory, denied_case, denial_command, denial_config, http, target=False)
            runner.record_call("durable_target_budget_denial", 403, http, denial_command)
        finally:
            runner.stop(process, lifecycle)
        denied_case["path"].unlink()
        process, base, lifecycle = runner.start(denial_state, "target_budget_restart_without_artifact")
        try:
            retry = runner.record_call("durable_target_budget_denial_retry", 403,
                                       runner.call(base, denial_token, "POST", "/api/admit", denial_command), denial_command)
            require(retry["result"]["replayed"] and retry["result"]["outcome"] == denied_result["outcome"], "target budget denial was not durably replayed")
            final = runner.record_call("target_budget_final_state", 200, runner.call(base, denial_token, "GET", "/api/state"))
            require(final["requests"][0]["status"] == "pending" and final["requests"][0]["revision"] == 1, "denial mutated target state")
        finally:
            runner.stop(process, lifecycle)
    require(sha(binary.read_bytes()) == binary_sha and source_inventory(project) == inventory, "binary or source bytes changed during observation")
    proof.update({"passed": True, "finished_at_utc": utc(), "cases": len(proof["observations"]),
                  "local_state_transitions": 2, "external_target_actions": 0,
                  "processes_exited_normally": len(proof["processes"]),
                  "unit_only_boundaries": ["injected precommit clock expiry", "long-after-expiry retry", "injected I/O faults", "snapshot byte capacity"]})
    assert_public(proof)
    raw = json.dumps(proof, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    runner.secret_free(raw)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    print(json.dumps({"passed": True, "cases": proof["cases"], "local_state_transitions": 2,
                      "normal_process_exits": proof["processes_exited_normally"], "external_target_actions": 0,
                      "raw_credentials_recorded": False, "proof_sha256": sha(raw)}))


if __name__ == "__main__":
    main()
