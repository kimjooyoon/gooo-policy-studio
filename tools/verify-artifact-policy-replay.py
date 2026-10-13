#!/usr/bin/env python3
"""Observe the compiled replay CLI with independent finite literal fixtures.

This stdlib observer never imports a product implementation or an earlier
checker as an expected-value oracle. The root task owns its first execution.
Retained reports and process output are stored once as exact byte documents;
directory snapshots reference those documents rather than duplicate them.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time


PROJECT = Path(__file__).resolve().parents[1]
MAX_REPORT = 64 << 20
SUMMARY_SCHEMA = "policy-studio/artifact-impact-replay-summary/v1"
COMPARISON_SCHEMA = "policy-studio/artifact-impact-summary/v1"
PROTECTED = {
    "model.go": "4cb0d55865afc9bdd548059785ad80a3353138f42af90731c8965384873560ab",
    "compare.go": "914f353751063bad60cbd0d0557b6346d17d7a52fd672fbf1852618fdac83128",
    "validate.go": "811c78666c0cdbf58c6d43f15b762b2ca66e5ffb2ebd3765edc776ddacd95e90",
    "delta.go": "640888b12d83d6203bb9735e3c85baedbb509877a4b3ad84ac69cc1bf1bc4a3d",
    "identity.go": "f98bbf34e9ef7d48f32d2341a702e8851d4e90cf87ce8b4d63d470c7b4f207b4",
    "files.go": "92b65942199e0fb740b9f823222e0ca19f965a658058750aad602d1978e32469",
    "files_unix.go": "fa8d93b0111a78ac7f56b11225944f3b517298a0a831aff14636ffd4af0388e5",
    "files_other.go": "71e48ad3de66a1ed9bc02892888fb3f73f6f484bc5baac51b6677824e13a0bf3",
}
DOC_ARTIFACT = b'{\n  "schema": "gooo/export-plan/v1",\n  "action": "prepare_export",\n  "destination": "internal",\n  "row_limit": 500,\n  "dry_run": true,\n  "format": "jsonl"\n}\n'
SIMPLE_ARTIFACT = b'{"schema":"replay.test/v1","destination":"internal"}'
COUNT_KEYS = ("total", "pass", "fail", "unsupported", "truncated", "unknown")


class ObservationFailure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(ok, code):
    if not ok:
        raise ObservationFailure(code)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def compact(value):
    # encoding/json emits UTF-8 and escapes these five characters even when
    # they occur in strings. Dict insertion order preserves the Go struct order
    # obtained from an actual retained report. No numbers are coerced to float.
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for old, new in (("&", r"\u0026"), ("<", r"\u003c"), (">", r"\u003e"),
                     ("\u2028", r"\u2028"), ("\u2029", r"\u2029")):
        text = text.replace(old, new)
    return text.encode("utf-8")


def decode(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "OBSERVER_DUPLICATE_JSON")
            out[key] = value
        return out
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ObservationFailure("OBSERVER_NONFINITE_JSON")))


def same_typed(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same_typed(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_typed(x, y) for x, y in zip(a, b))
    return a == b


def counts(total=0, passed=0, failed=0, unsupported=0, truncated=0, unknown=0):
    return dict(zip(COUNT_KEYS, (total, passed, failed, unsupported, truncated, unknown)))


def side(allow=False, reason="", values=None):
    return {"would_admit": allow, "reason": reason, "counts": values or counts()}


def replay_summary(code="HISTORICAL_COMPARISON_MATCH", direction="", before=None, after=None,
                   added=0, removed=0, changed=0, order=False, recipe=False,
                   budget=False, checks=False, verifier=""):
    verified = code == "HISTORICAL_COMPARISON_MATCH"
    return {
        "schema": SUMMARY_SCHEMA, "status": "verified" if verified else "error", "code": code,
        "historical": True, "simulation": True, "read_only": True,
        "authenticated_server_state": False, "committed": False, "target_effects_executed": False,
        "current_artifact_reads": 0, "direction": direction, "before": before or side(), "after": after or side(),
        "added_claims": added, "removed_claims": removed, "changed_claims": changed,
        "claim_order_changed": order, "recipe_configuration_changed": recipe,
        "approval_budget_changed": budget, "approval_checks_changed": checks, "verifier_sha256": verifier,
    }


def comparison_summary(literal):
    return {
        "schema": COMPARISON_SCHEMA, "status": "compared", "code": "COMPARISON_SAVED",
        "simulation": True, "report_saved": True,
        **{k: copy.deepcopy(literal[k]) for k in (
            "direction", "before", "after", "added_claims", "removed_claims", "changed_claims",
            "claim_order_changed", "recipe_configuration_changed", "approval_budget_changed", "approval_checks_changed")},
    }


def budget(target):
    return {"allow_target": target, "allow_session": True, "allow_filesystem": True,
            "allow_process": False, "allow_network": False, "allow_ui": False,
            "allow_discard": False, "allow_foreign_code": False, "allow_device": False,
            "require_idempotent": True}


def policy(n=5):
    if n == 5:
        fields = [{"name": "action", "type": "text"}, {"name": "destination", "type": "text"},
                  {"name": "row_limit", "type": "int64"}, {"name": "dry_run", "type": "bool"},
                  {"name": "format", "type": "text"}]
        claim_values = [("action_equal", "action", "prepare_export"),
                        ("destination_equal", "destination", "internal"),
                        ("row_limit_equal", "row_limit", "500"),
                        ("dry_run_equal", "dry_run", "true"), ("format_equal", "format", "jsonl")]
        artifact_schema = "gooo/export-plan/v1"
    else:
        fields = [{"name": "destination", "type": "text"}]
        claim_values = [(f"claim_{i:03d}", "destination", "internal") for i in range(n)]
        artifact_schema = "replay.test/v1"
    return {
        "schema": "policy-studio/artifact-admission-policy/v1", "id": "replay-fixture", "revision": 1,
        "recipe": {"schema": "policy-studio/artifact-recipe/v1", "producer_id": "flat-json/v1",
                   "artifact_schema": artifact_schema, "max_bytes": 65536, "fields": fields,
                   "claims": [{"id": name, "verifier": "field_equals/v1", "field": field, "expected": value}
                              for name, field, value in claim_values]},
        "required_authority": "live-observation", "max_age_seconds": 60,
        "approval_budget": budget(True), "control_plane_budget": budget(False),
    }


def case_value(artifact_path, raw, deadline=4102444800):
    return {
        "schema": "policy-studio/artifact-impact-case/v1",
        "request": {"key": "private-replay-request", "requester": "operator", "team": "platform",
                    "amount": 0, "submitted": True},
        "principal": {"key": "private-replay-principal", "team": "platform", "active": True,
                      "enabled": True, "can_execute": True},
        "base_rules": {"limit": 1000000, "same_team": True, "active_reviewer": True, "prevent_self": True},
        "artifact": {"path": str(artifact_path), "expected_sha256": sha(raw), "deadline_unix": deadline},
    }


def literals():
    """All expected outcomes are chosen before any child is invoked."""
    out = []
    def add(name, n=5, bpass=None, apass=None, breason="ADMITTED", areason="ADMITTED",
            badmit=True, aadmit=True, category="pass", direction="unchanged", changed=0,
            recipe=False, budget_changed=False, checks=False, added=0, removed=0, order=False):
        bpass = n if bpass is None else bpass
        apass = n if apass is None else apass
        if category == "unknown":
            bc, ac = counts(n, unknown=n), counts(n, unknown=n)
        elif category == "truncated":
            bc, ac = counts(n, truncated=n), counts(n, truncated=n)
        else:
            bc, ac = counts(n, bpass, n - bpass), counts(n, apass, n - apass)
        if name == "claim_added": ac = counts(2, 2)
        if name == "claim_removed": bc, ac = counts(2, 2), counts(1, 1)
        expected = replay_summary(direction=direction, before=side(badmit, breason, bc), after=side(aadmit, areason, ac),
                                  added=added, removed=removed, changed=changed, order=order, recipe=recipe,
                                  budget=budget_changed, checks=checks)
        out.append({"id": name, "claims": n, "expected_summary": expected})
    add("expired_now_history", n=1)
    add("newly_denied", apass=4, areason="EVIDENCE_REJECTED", aadmit=False,
        direction="newly_denied", changed=1, recipe=True)
    add("newly_allowed", bpass=4, breason="EVIDENCE_REJECTED", badmit=False,
        direction="newly_allowed", changed=1, recipe=True)
    add("one_claim", n=1)
    add("all_256", n=256)
    for name in ("failure_256_first", "failure_256_middle", "failure_256_last"):
        add(name, n=256, apass=255, areason="EVIDENCE_REJECTED", aadmit=False,
            direction="newly_denied", changed=1, recipe=True)
    add("base_denied", category="unknown", badmit=False, aadmit=False,
        breason="BASE_POLICY_DENIED", areason="BASE_POLICY_DENIED")
    add("principal_disabled", category="unknown", badmit=False, aadmit=False,
        breason="PROPOSED_PRINCIPAL_DISABLED", areason="PROPOSED_PRINCIPAL_DISABLED")
    add("execution_forbidden", category="unknown", badmit=False, aadmit=False,
        breason="PROPOSED_EXECUTION_FORBIDDEN", areason="PROPOSED_EXECUTION_FORBIDDEN")
    add("approval_budget_denied", aadmit=False, areason="OPERATION_EFFECT_DISALLOWED",
        direction="newly_denied", budget_changed=True, checks=True)
    add("approval_budget_unused", budget_changed=True)
    add("expired_evidence", badmit=False, aadmit=False, breason="EVIDENCE_REJECTED", areason="EVIDENCE_REJECTED")
    add("digest_rejected", bpass=0, apass=0, badmit=False, aadmit=False,
        breason="EVIDENCE_REJECTED", areason="EVIDENCE_REJECTED")
    add("artifact_missing", category="unknown", badmit=False, aadmit=False,
        breason="EVIDENCE_REJECTED", areason="EVIDENCE_REJECTED")
    add("artifact_oversized", category="truncated", badmit=False, aadmit=False,
        breason="EVIDENCE_REJECTED", areason="EVIDENCE_REJECTED")
    add("artifact_malformed", bpass=0, apass=0, badmit=False, aadmit=False,
        breason="EVIDENCE_REJECTED", areason="EVIDENCE_REJECTED")
    add("schema_changed", apass=0, aadmit=False, areason="EVIDENCE_REJECTED",
        direction="newly_denied", changed=5, recipe=True)
    add("field_type_changed", apass=0, aadmit=False, areason="EVIDENCE_REJECTED",
        direction="newly_denied", changed=5, recipe=True)
    add("claim_added", n=1, added=1, recipe=True)
    add("claim_removed", n=2, removed=1, recipe=True)
    add("claims_reordered", order=True)
    return out


def inventory():
    paths = {PROJECT / "go.mod", Path(__file__).resolve()}
    if (PROJECT / "go.sum").exists(): paths.add(PROJECT / "go.sum")
    for top in ("cmd", "internal", "examples", "docs", ".github"):
        for p in (PROJECT / top).rglob("*"):
            if p.is_file() and p.suffix in (".go", ".gooo", ".json", ".md", ".yml", ".yaml"):
                paths.add(p)
    paths.add(PROJECT / "README.md")
    return [{"path": str(p.relative_to(PROJECT)), "bytes": p.stat().st_size,
             "sha256": sha(p.read_bytes()), "mode": stat.S_IMODE(p.stat().st_mode)}
            for p in sorted(paths)]


def binary_binding(path):
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111), "BINARY_INVALID")
    return {"path": str(path), "bytes": info.st_size, "sha256": sha(path.read_bytes()),
            "mode": stat.S_IMODE(info.st_mode)}


class Observer:
    def __init__(self, args):
        self.args = args
        self.impact = Path(args.impact_bin).resolve()
        self.legacy = Path(args.legacy_impact_bin or args.impact_bin).resolve()
        self.root = None
        self.verifier = None
        self.fixtures = {}
        self.live = []
        self.proof = {
            "schema": "gooo-artifact-policy-replay-observer/v1", "passed": False,
            "started_unix_ns": time.time_ns(), "legacy_binary_explicit": bool(args.legacy_impact_bin),
            "legacy_mode": "separate_closed_binary" if args.legacy_impact_bin else "current_binary_unchanged_comparison_format",
            "limitations": [
                "Finite recorded CLI cases check historical self-consistency, not issuer authentication or current permission.",
                "No server, credential, gate process, admission commit or target action is created.",
                "A coherently rewritten unsigned report may remain internally consistent.",
                "Cross-platform or Go-version histories intentionally fail; this observer uses matching local generation and replay binaries.",
                "Oversized sparse private input is streamed and checked but its greater-than-limit bytes are not duplicated in the proof.",
            ],
            "documents": {}, "comparison_fixtures": [], "replay_cases": [], "processes": [],
            "literal_catalog": literals(), "source_inventory_before": [], "source_inventory_after": [],
            "binary_before": {}, "binary_after": {}, "failure": None,
        }

    def document(self, raw):
        identity = sha(raw)
        entry = {"bytes": len(raw), "sha256": identity, "raw_base64": base64.b64encode(raw).decode("ascii")}
        if identity in self.proof["documents"]:
            require(self.proof["documents"][identity] == entry, "DOCUMENT_COLLISION")
        else:
            self.proof["documents"][identity] = entry
        return identity

    def snapshot(self, root):
        entries = []
        def walk(parent):
            for p in sorted(parent.iterdir()):
                info = p.lstat()
                entry = {"path": str(p.relative_to(root)), "mode": stat.S_IMODE(info.st_mode),
                         "size": info.st_size, "inode": info.st_ino, "device": info.st_dev,
                         "mtime_ns": info.st_mtime_ns}
                if stat.S_ISDIR(info.st_mode):
                    entry["type"] = "directory"
                    entries.append(entry)
                    walk(p)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    entry.update(type="symlink", target=os.readlink(p))
                elif stat.S_ISFIFO(info.st_mode):
                    entry["type"] = "fifo"
                elif stat.S_ISREG(info.st_mode):
                    entry["type"] = "regular"
                    if info.st_size > MAX_REPORT:
                        h = hashlib.sha256()
                        zero = True
                        total = 0
                        with p.open("rb") as f:
                            for block in iter(lambda: f.read(1 << 20), b""):
                                total += len(block)
                                h.update(block)
                                zero = zero and not any(block)
                        entry.update(sha256="sha256:" + h.hexdigest(), streamed_bytes=total,
                                     oversized=True, all_zero=zero, raw_not_captured=True)
                    else:
                        raw = p.read_bytes()
                        require(len(raw) == info.st_size, "SNAPSHOT_SIZE_CHANGED")
                        entry["document"] = self.document(raw)
                else:
                    entry["type"] = "other"
                entries.append(entry)
        walk(root)
        return entries

    def process(self, argv, role):
        record = {"role": role, "argv": [str(x) for x in argv], "started_unix_ns": time.time_ns(),
                  "spawn_attempted": True, "spawned": False, "completed": False,
                  "timed_out": False, "exit": None}
        self.proof["processes"].append(record)
        try:
            child = subprocess.Popen(record["argv"], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=str(PROJECT), env={**os.environ, "GOTOOLCHAIN": "local"})
            record["spawned"] = True
            self.live.append((child, record))
        except OSError:
            raise ObservationFailure("PROCESS_SPAWN_FAILED") from None
        captured = True
        try:
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            try:
                child.kill()
                stdout, stderr = child.communicate(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.reap(child, record)
                raise ObservationFailure("PROCESS_REAP_FAILED") from None
        except BaseException:
            captured = False
            self.reap(child, record)
            record["output_capture_complete"] = False
            raise ObservationFailure("PROCESS_CAPTURE_FAILED") from None
        # Retain an actual completed exit before decoding/semantic assertions.
        record.update(completed=True, exit=child.returncode, ended_unix_ns=time.time_ns(),
                      stdout=self.document(stdout), stderr=self.document(stderr), output_capture_complete=captured)
        self.live.remove((child, record))
        require(not record["timed_out"], "PROCESS_TIMEOUT")
        require(len(stdout) <= 65536 and len(stderr) <= 65536, "PROCESS_OUTPUT_OVERSIZED")
        return record, stdout, stderr

    def reap(self, child, record):
        # A bounded emergency kill/wait is used on every capture failure and
        # again at finalization if needed. No gate or background process exists.
        try:
            if child.poll() is None: child.kill()
            child.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            record["cleanup_failed"] = True
        else:
            record.update(completed=True, exit=child.returncode, ended_unix_ns=time.time_ns())
            if (child, record) in self.live: self.live.remove((child, record))
        for pipe in (child.stdout, child.stderr):
            if pipe is not None:
                try: pipe.close()
                except OSError: pass

    def write(self, path, raw):
        with path.open("xb") as f:
            os.chmod(path, 0o600)
            f.write(raw)
        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "FIXTURE_MODE_INVALID")

    def bind_verifier(self, report):
        host = report["implementation"]["host_sources"]
        require({x["path"]: x["sha256"][7:] for x in host} == PROTECTED, "OLD_PRODUCER_SOURCE_CHANGED")
        current = {p["path"]: p["sha256"] for p in self.proof["source_inventory_before"]}
        for name, digest in PROTECTED.items():
            require(current["internal/artifactimpact/" + name] == "sha256:" + digest, "OLD_SOURCE_BYTES_CHANGED")
        identity = {
            "schema": "policy-studio/artifact-impact-replay-source/v1",
            "sources": [{"path": name, "sha256": current["internal/artifactimpact/" + name]}
                        for name in ("replay.go", "replay_identity.go", "replay_files.go")],
            "comparison": copy.deepcopy(report["implementation"]), "verifier_sha256": "",
        }
        identity["verifier_sha256"] = sha(compact(identity))
        if self.verifier is not None:
            require(same_typed(identity, self.verifier), "FIXTURE_IMPLEMENTATION_CHANGED")
        self.verifier = identity
        self.proof["verifier_identity"] = identity

    def make_fixture(self, literal):
        name, n = literal["id"], literal["claims"]
        folder = self.root / name
        folder.mkdir(mode=0o700)
        artifact = folder / "artifact.json"
        raw = DOC_ARTIFACT if n == 5 else SIMPLE_ARTIFACT
        before, after = policy(n), policy(n)
        c = case_value(artifact, raw)
        after["revision"] = 2
        if name == "expired_now_history":
            c["artifact"]["deadline_unix"] = int(time.time()) + 3
        elif name == "newly_denied": after["recipe"]["claims"][1]["expected"] = "external"
        elif name == "newly_allowed": before["recipe"]["claims"][1]["expected"] = "external"
        elif name.startswith("failure_256_"):
            index = {"first": 0, "middle": 128, "last": 255}[name.rsplit("_", 1)[1]]
            after["recipe"]["claims"][index]["expected"] = "external"
        elif name == "base_denied": c["request"]["submitted"] = False
        elif name == "principal_disabled": c["principal"]["enabled"] = False
        elif name == "execution_forbidden": c["principal"]["can_execute"] = False
        elif name == "approval_budget_denied": after["approval_budget"]["allow_target"] = False
        elif name == "approval_budget_unused": after["approval_budget"]["allow_network"] = True
        elif name == "expired_evidence": c["artifact"]["deadline_unix"] = 1
        elif name == "digest_rejected": c["artifact"]["expected_sha256"] = "sha256:" + "0" * 64
        elif name == "artifact_oversized": raw = b"x" * 65537; c["artifact"]["expected_sha256"] = sha(raw)
        elif name == "artifact_malformed": raw = b'{"schema":'; c["artifact"]["expected_sha256"] = sha(raw)
        elif name == "schema_changed": after["recipe"]["artifact_schema"] = "replay.other/v1"
        elif name == "field_type_changed":
            after["recipe"]["fields"][1]["type"] = "bool"
            after["recipe"]["claims"][1]["expected"] = "true"
        elif name == "claim_added":
            after = policy(2); after["revision"] = 2
        elif name == "claim_removed":
            after = policy(1); after["revision"] = 2
        elif name == "claims_reordered":
            after["recipe"]["claims"][0], after["recipe"]["claims"][4] = after["recipe"]["claims"][4], after["recipe"]["claims"][0]
        paths = {key: folder / (key + ".json") for key in ("case", "before", "after", "report")}
        inputs = {"case": c, "before": before, "after": after}
        input_docs = {}
        for key, value in inputs.items():
            encoded = compact(value) + b"\n"
            self.write(paths[key], encoded)
            input_docs[key] = self.document(encoded)
        if name != "artifact_missing": self.write(artifact, raw)
        observed = {"id": name, "literal": copy.deepcopy(literal), "inputs": inputs,
                    "input_documents": input_docs, "artifact_document": self.document(raw),
                    "artifact_initially_missing": name == "artifact_missing", "folder": str(folder),
                    "directory_before_comparison": self.snapshot(folder),
                    "expected_comparison_summary": comparison_summary(literal["expected_summary"])}
        self.proof["comparison_fixtures"].append(observed)
        process, stdout, stderr = self.process([self.legacy, "compare", "--case", paths["case"],
                                                "--before", paths["before"], "--after", paths["after"],
                                                "--report", paths["report"]], "legacy_comparison")
        observed["process_index"] = self.proof["processes"].index(process)
        observed["directory_after_comparison"] = self.snapshot(folder)
        require(process["exit"] == 0 and stderr == b"", "LEGACY_COMPARISON_FAILED")
        require(same_typed(decode(stdout), observed["expected_comparison_summary"]), "LEGACY_LITERAL_MISMATCH")
        observed["comparison_summary_checked"] = True
        report_raw = paths["report"].read_bytes()
        report = decode(report_raw)
        observed["report_document"] = self.document(report_raw)
        observed["report"] = report
        observed["report_mode"] = stat.S_IMODE(paths["report"].stat().st_mode)
        require(observed["report_mode"] == 0o600, "LEGACY_REPORT_NOT_PRIVATE")
        self.bind_verifier(report)
        for key in ("case", "before", "after"): paths[key].unlink()
        if artifact.exists(): artifact.unlink()
        observed["directory_after_original_removal"] = self.snapshot(folder)
        self.fixtures[name] = (observed, folder, paths["report"], artifact)

    def replay(self, fixture_name, name, path=None, raw=None, mutation=None, code="HISTORICAL_COMPARISON_MATCH", extra_args=None):
        observed, folder, original_path, _ = self.fixtures[fixture_name]
        path = path or original_path
        expected = copy.deepcopy(observed["literal"]["expected_summary"])
        if code != "HISTORICAL_COMPARISON_MATCH": expected = replay_summary(code=code)
        else: expected["verifier_sha256"] = self.verifier["verifier_sha256"]
        record = {"id": name, "fixture": fixture_name, "input_path": str(path),
                  "expected": {"exit": 0 if code == "HISTORICAL_COMPARISON_MATCH" else 2, "summary": expected},
                  "mutation": mutation, "directory_before": self.snapshot(folder)}
        if raw is not None: record["input_document"] = self.document(raw)
        elif path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_REPORT:
            record["input_document"] = self.document(path.read_bytes())
        self.proof["replay_cases"].append(record)
        process, stdout, stderr = self.process([self.impact, "replay", *(extra_args if extra_args is not None else ["--report", path])], "historical_replay")
        record["process_index"] = self.proof["processes"].index(process)
        record["directory_after"] = self.snapshot(folder)
        record["directory_unchanged"] = same_typed(record["directory_before"], record["directory_after"])
        require(record["directory_unchanged"], "REPLAY_CHANGED_DIRECTORY")
        require(process["exit"] == record["expected"]["exit"] and stderr == b"", "REPLAY_PROCESS_MISMATCH")
        require(same_typed(decode(stdout), expected), "REPLAY_LITERAL_MISMATCH")
        require(original_path.read_bytes() == base64.b64decode(self.proof["documents"][observed["report_document"]]["raw_base64"]), "ORIGINAL_REPORT_CHANGED")
        record["checked"] = True

    def valid_cases(self):
        # Historical expiry uses a genuine prior accepted comparison. No saved
        # clock or evidence is synthesized from a replay result.
        for item in self.proof["literal_catalog"]: self.make_fixture(item)
        for name in self.fixtures:
            if name != "expired_now_history": self.replay(name, "historical_" + name)
        observed, _, _, _ = self.fixtures["expired_now_history"]
        deadline = observed["inputs"]["case"]["artifact"]["deadline_unix"]
        require(observed["report"]["observation_unix"] < deadline, "EXPIRY_FIXTURE_MISSED_WINDOW")
        before = time.time_ns()
        wait_until = time.monotonic() + 4
        while int(time.time()) < deadline and time.monotonic() < wait_until:
            time.sleep(0.02)
        after = time.time_ns()
        require(int(time.time()) >= deadline, "HISTORICAL_EXPIRY_WAIT_FAILED")
        observed["expired_now_observation"] = {"deadline_unix": deadline, "before_unix_ns": before,
                                               "after_unix_ns": after, "bounded_wait_seconds": 4}
        self.replay("expired_now_history", "historical_expired_now")
        _, folder, original, artifact = self.fixtures["newly_denied"]
        os.symlink("nonexistent-current-artifact", artifact)
        self.replay("newly_denied", "current_artifact_symlink")
        artifact.unlink()
        os.mkfifo(artifact, 0o600)
        self.replay("newly_denied", "current_artifact_fifo")
        artifact.unlink()
        alias = folder / "parent-alias"
        os.symlink(folder, alias)
        self.replay("newly_denied", "administrative_parent_alias", path=alias / original.name)
        alias.unlink()

    def mutations(self):
        observed, folder, _, _ = self.fixtures["newly_denied"]
        zero_sha = "sha256:" + "0" * 64
        # Each literal path reaches a different retained stage. Rehashing only
        # the outer ID defeats a mere top-level checksum check, not replay.
        targets = [
            (("schema",), "policy-studio/wrong/v1"), (("scope",), "private-forged-scope"),
            (("simulation",), False), (("authenticated_server_state",), True),
            (("committed",), True), (("target_effects_executed",), True), (("observation_unix",), 1),
            (("inputs", "case", "raw_sha256"), zero_sha), (("inputs", "before", "semantic_sha256"), zero_sha),
            (("implementation", "host_sha256"), zero_sha), (("implementation", "go_version"), "go0.invalid"),
            (("implementation", "goos"), "unknown"), (("implementation", "host_sources", 0, "sha256"), zero_sha),
            (("permission", "eligible"), False), (("permission", "modeled_http_status"), 401),
            (("base_receipt", "created_at"), "private-malformed-time"),
            (("base_receipt", "input", "request", "submitted"), False),
            (("base_receipt", "result", "after", "approved"), False),
            (("base_receipt", "source_sha256"), zero_sha),
            (("before", "context_sha256"), zero_sha), (("after", "simulation_policy_version"), zero_sha),
            (("before", "context", "side"), "after"),
            (("after", "context", "case", "artifact", "deadline_unix"), 1),
            (("before", "producer", "artifact_base64"), base64.b64encode(b"private-forged-bytes").decode()),
            (("before", "producer", "actual_sha256"), zero_sha),
            (("before", "producer", "observed_size"), 999),
            (("before", "producer", "acquisition_status"), "skipped"),
            (("before", "producer", "recipe_sha256"), zero_sha),
            (("before", "producer", "identity", "verifier_sha256"), zero_sha),
            (("after", "producer", "observations", 1, "status"), "pass"),
            (("after", "producer", "observations", 1, "evidence_id"), "ev_" + "0" * 64),
            (("before", "evidence", 0, "facts", "provider_verified"), False),
            (("after", "evidence", 1, "decision", "admissible"), True),
            (("before", "completion", "input", "records", 0, "status"), "fail"),
            (("before", "completion", "steps", 0, "counts_before", "pass"), 1),
            (("before", "completion", "steps", 2, "decision", "pass"), 0),
            (("before", "completion", "steps", 4, "decision", "total"), 4),
            (("before", "completion", "coverage", "matched_count"), 4),
            (("after", "completion", "summary", "pass"), 5),
            (("after", "completion", "readiness", "ready"), True),
            (("before", "completion", "bindings", "source_sha256"), zero_sha),
            (("before", "proposed_approval", "facts", "mutatesTarget"), False),
            (("before", "proposed_approval", "budget", "allow_target"), False),
            (("before", "proposed_approval", "decision", "admissible"), False),
            (("before", "proposed_control_plane", "facts", "accessesNetwork"), True),
            (("before", "admission_facts", "admissible_evidence_count"), 0),
            (("before", "decision", "admitted"), False), (("before", "reason"), "EVIDENCE_REJECTED"),
            (("after", "would_admit"), True), (("delta", "direction"), "newly_allowed"),
            (("delta", "changed", 0, "predicate_changed"), False),
            (("delta", "recipe_configuration_changed"), False),
            (("audit", "artifact_read_attempts"), 0), (("audit", "effects", "mutatesTarget"), True),
            (("audit", "private_report_write_planned"), False),
        ]
        for index, (path, replacement) in enumerate(targets):
            report = copy.deepcopy(observed["report"])
            value = report
            for part in path[:-1]: value = value[part]
            old = copy.deepcopy(value[path[-1]])
            require(not same_typed(old, replacement), "TAMPER_NOT_DISTINCT")
            value[path[-1]] = replacement
            report["id"] = ""
            report["id"] = sha(compact(report))
            raw = compact(report) + b"\n"
            target = folder / f"tamper-{index:02d}.json"
            self.write(target, raw)
            self.replay("newly_denied", f"nested_tamper_{index:02d}", path=target, raw=raw,
                        code="REPORT_REPLAY_INVALID", mutation={"path": list(path), "previous": old,
                            "replacement": replacement, "outer_id_rehashed": True})
            target.unlink()
        # A valid but unsigned timestamp rewrite with both checksums recomputed
        # remains internally consistent. This is an explicit authenticity limit.
        report = copy.deepcopy(observed["report"])
        report["base_receipt"]["created_at"] = "2100-01-01T00:00:00.123456789Z"
        report["base_receipt"]["id"] = ""
        report["base_receipt"]["id"] = sha(compact(report["base_receipt"]))
        report["id"] = ""
        report["id"] = sha(compact(report))
        raw = compact(report) + b"\n"
        target = folder / "unsigned-coherent-timestamp.json"
        self.write(target, raw)
        self.replay("newly_denied", "unsigned_coherent_timestamp_not_authentication", path=target, raw=raw,
                    mutation={"path": ["base_receipt", "created_at"], "replacement": "2100-01-01T00:00:00.123456789Z",
                              "base_id_rehashed": True, "outer_id_rehashed": True, "expected_internal_consistency": True})
        target.unlink()

    def invalid_inputs(self):
        observed, folder, _, _ = self.fixtures["newly_denied"]
        original = base64.b64decode(self.proof["documents"][observed["report_document"]]["raw_base64"])
        def edit(change):
            value = copy.deepcopy(observed["report"])
            change(value)
            return compact(value) + b"\n"
        cases = [
            ("json_duplicate", b'{"schema":"private-duplicate",' + original.lstrip()[1:]),
            ("json_trailing", original + b' {"private-trailing":true}'),
            ("json_missing", edit(lambda x: x.pop("scope"))),
            ("json_unknown", edit(lambda x: x.update({"private-unknown": True}))),
            ("json_null", edit(lambda x: x.update({"before": None}))),
            ("json_wrong_type", edit(lambda x: x.update({"committed": "false"}))),
            ("json_unicode", b'{"schema":"\\ud800-private"}'),
            ("json_invalid_utf8", b'{"schema":"\xff-private"}'),
            ("json_empty", b""),
            ("json_nested_duplicate", original.replace(b'"would_admit": true', b'"would_admit":false,"would_admit":true', 1)),
        ]
        for name, raw in cases:
            target = folder / (name + ".json")
            self.write(target, raw)
            self.replay("newly_denied", name, path=target, raw=raw, code="REPORT_JSON_INVALID")
            target.unlink()
        for name in ("input_missing", "input_public_mode", "input_symlink", "input_fifo", "input_oversize"):
            target = folder / (name + ".json")
            if name == "input_public_mode": self.write(target, original); target.chmod(0o644)
            elif name == "input_symlink": os.symlink("report.json", target)
            elif name == "input_fifo": os.mkfifo(target, 0o600)
            elif name == "input_oversize":
                self.write(target, b"")
                with target.open("r+b") as f: f.truncate(MAX_REPORT + 1)
            self.replay("newly_denied", name, path=target, code="REPORT_FILE_INVALID")
            if name != "input_missing": target.unlink()
        report = folder / "report.json"
        cli = [
            ("flags_missing", []), ("flags_empty_report", ["--report", ""]),
            ("flags_repeated", ["--report", report, "--report", report]),
            ("flags_clock_override", ["--report", report, "--now", "private-clock"]),
            ("flags_before_override", ["--report", report, "--before", "private-input"]),
            ("flags_after_override", ["--report", report, "--after", "private-input"]),
            ("flags_case_override", ["--report", report, "--case", "private-input"]),
            ("flags_extra", ["--report", report, "private-extra"]),
        ]
        for name, flags in cli:
            self.replay("newly_denied", name, code="USAGE_INVALID", extra_args=flags)

    def run(self):
        require(sha(DOC_ARTIFACT) == "sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533", "LITERAL_ARTIFACT_SHA_CHANGED")
        require((PROJECT / "examples/artifact-impact/artifact.json").read_bytes() == DOC_ARTIFACT, "DOCUMENTED_ARTIFACT_CHANGED")
        self.proof["source_inventory_before"] = inventory()
        self.proof["binary_before"] = {"impact": binary_binding(self.impact), "legacy": binary_binding(self.legacy)}
        if self.args.workdir:
            self.root = Path(self.args.workdir).resolve()
            self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
        else:
            self.root = Path(tempfile.mkdtemp(prefix="gooo-artifact-replay-")).resolve()
            self.root.chmod(0o700)
        self.proof["workdir"] = str(self.root)
        self.valid_cases()
        self.mutations()
        self.invalid_inputs()
        self.proof["source_inventory_after"] = inventory()
        self.proof["binary_after"] = {"impact": binary_binding(self.impact), "legacy": binary_binding(self.legacy)}
        require(same_typed(self.proof["source_inventory_before"], self.proof["source_inventory_after"]), "SOURCE_CHANGED_DURING_OBSERVATION")
        require(same_typed(self.proof["binary_before"], self.proof["binary_after"]), "BINARY_CHANGED_DURING_OBSERVATION")
        self.proof["passed"] = True

    def finish(self):
        # Counts derive from completed records even when a later assertion fails.
        for child, record in list(self.live): self.reap(child, record)
        if self.live:
            self.proof["passed"] = False
            self.proof["failure"] = {"code": "PROCESS_FINAL_CLEANUP_FAILED"}
        try:
            if not self.proof["source_inventory_after"]: self.proof["source_inventory_after"] = inventory()
            if not self.proof["binary_after"]:
                self.proof["binary_after"] = {"impact": binary_binding(self.impact), "legacy": binary_binding(self.legacy)}
        except Exception:
            self.proof["final_binding_capture_failed"] = True
            self.proof["passed"] = False
            if self.proof["failure"] is None: self.proof["failure"] = {"code": "FINAL_BINDING_CAPTURE_FAILED"}
        records = self.proof["processes"]
        self.proof["counts"] = {
            "spawn_attempts": sum(x["spawn_attempted"] for x in records),
            "spawned": sum(x["spawned"] for x in records), "completed": sum(x["completed"] for x in records),
            "normal_exits": sum(x["completed"] and x["exit"] is not None and x["exit"] >= 0 for x in records),
            "legacy_comparisons": sum(x["role"] == "legacy_comparison" and x["completed"] for x in records),
            "replay_calls": sum(x["role"] == "historical_replay" and x["completed"] for x in records),
            "verified_replays": sum(x["role"] == "historical_replay" and x["completed"] and x["exit"] == 0 for x in records),
            "rejected_replays": sum(x["role"] == "historical_replay" and x["completed"] and x["exit"] == 2 for x in records),
            "unexpected_replay_exits": sum(x["role"] == "historical_replay" and x["completed"] and x["exit"] not in (0, 2) for x in records),
            "checked_replays": sum(x.get("checked", False) for x in self.proof["replay_cases"]),
            "checked_verified_replays": sum(x.get("checked", False) and x["expected"]["exit"] == 0 for x in self.proof["replay_cases"]),
            "checked_rejected_replays": sum(x.get("checked", False) and x["expected"]["exit"] == 2 for x in self.proof["replay_cases"]),
            "gate_initializations": 0, "gate_starts": 0, "admission_commits": 0, "target_actions": 0,
        }
        self.proof["finished_unix_ns"] = time.time_ns()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--impact-bin", required=True)
    parser.add_argument("--legacy-impact-bin", help="Optional previously closed comparator; CI defaults to the current unchanged comparison format")
    parser.add_argument("--proof", required=True)
    parser.add_argument("--workdir", help="New private observation directory; must not exist")
    args = parser.parse_args()
    observer = Observer(args)
    try:
        observer.run()
    except ObservationFailure as error:
        observer.proof["failure"] = {"code": error.code}
    except BaseException:
        observer.proof["failure"] = {"code": "OBSERVER_INTERNAL_FAILURE"}
    finally:
        observer.finish()
        raw = compact(observer.proof) + b"\n"
        destination = Path(args.proof)
        try:
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            print(json.dumps({"schema": "gooo-artifact-policy-replay-observer-summary/v1", "passed": False,
                              "code": "PROOF_SAVE_FAILED"}, separators=(",", ":")))
            return 1
    print(json.dumps({"schema": "gooo-artifact-policy-replay-observer-summary/v1",
                      "passed": observer.proof["passed"], "counts": observer.proof["counts"]}, separators=(",", ":")))
    return 0 if observer.proof["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
