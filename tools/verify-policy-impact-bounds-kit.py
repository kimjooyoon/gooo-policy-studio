#!/usr/bin/env python3
"""Check one source-bound bounds-profile archive and optionally its three calls.

Static legacy parsers are reused as library functions, never their demo or old
oracle. Finite expected judgments below are handwritten before any new run.
No compiler, build, network or browser is invoked. --run-demo is explicit.
"""
import argparse
import base64
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import os
import platform
import re
import signal
import stat
import struct
import sys
import tempfile
import time
import warnings
import zipfile
from html.parser import HTMLParser
from pathlib import Path


def library(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


old = library("policy_impact_static", "verify-policy-impact-kit.py")
require, Rejected = old.require, old.Rejected
exact, strict_json, digest, hash_value = old.exact, old.strict_json, old.digest, old.hash_value
SEEDS = ("case-row-501.json", "artifact-row-501.json", "policy-before-upper-1000.json", "policy-after-upper-500.json")
SEED_SHA = ("19415ac36509f9c2a1c43de10542a137362691d75f4e1f605d711155791fa654",
            "e6766b36e840581b461fb698048e71622c1f22dc2184460f1431fe42f0171653",
            "42bcb80d043fba24ead755d630c6c11327b965d4bbae5bc7483a9d40923a5816",
            "2da140386d88014b93343d89c8737620944fab73600a31a07643a59ca0af4d9e")
DOCS = ("artifact-bounds-first-use.md", "artifact-int64-bounds.md", "artifact-policy-explain.md", "artifact-policy-impact.md", "artifact-policy-replay.md")
CLAIMS = ("action_equal", "destination_equal", "row_limit_at_least", "row_limit_at_most", "dry_run_equal", "format_equal")
CLAIM_HEADERS = ["Claim", "Required", "Verifier", "Field", "Expected", "Status", "Actual", "Reason", "Evidence admissible", "Evidence reason"]
# Literal native truths, not host comparisons or facts learned from answers.
GTE_ZERO = {"facts": {"value": 501, "bound": 0, "operator": "gte"},
            "decision": {"at_most": False, "at_least": True, "operator_ok": True, "matched": True, "reason": "BOUND_MATCH"}}
LTE_1000 = {"facts": {"value": 501, "bound": 1000, "operator": "lte"},
            "decision": {"at_most": True, "at_least": False, "operator_ok": True, "matched": True, "reason": "BOUND_MATCH"}}
LTE_500 = {"facts": {"value": 501, "bound": 500, "operator": "lte"},
           "decision": {"at_most": False, "at_least": True, "operator_ok": True, "matched": False, "reason": "BOUND_MISMATCH"}}
COUNTS_BEFORE = ((0, 0, 0), (1, 1, 0), (2, 2, 0), (3, 3, 0), (4, 4, 0), (5, 5, 0), (6, 6, 0))
COUNTS_AFTER = ((0, 0, 0), (1, 1, 0), (2, 2, 0), (3, 3, 0), (4, 3, 1), (5, 4, 1), (6, 5, 1))
COMPLETE_BEFORE = (True, True, True, True, True, True)
COMPLETE_AFTER = (True, True, True, False, False, False)
REPORT_SCOPE = "Finite comparison of two proposed v2 policies over one local artifact acquisition. Proposed principal facts are not authenticated server state; no admission is committed and no target effect is executed. Source hashes check implementation consistency, not issuer authenticity or production safety."
BASE_SCOPE = "One request, two parameter sets, compiled Gooo activities; not a full-domain proof or a signed audit record."
WORK_PATTERN = r"/(?:private/)?tmp/gooo-policy-impact-bounds\.[A-Za-z0-9]+"
FINITE_FILE = 1 << 20


def counts(row):
    total, passed, failed = row
    return dict(total=total, **{"pass": passed}, fail=failed, unsupported=0, truncated=0, unknown=0)


def identities(source, target):
    comparison, verifier = old.identity_for(source, target)
    h = lambda name: "sha256:" + digest(source["internal/artifactimpact/" + name])
    replay = {"schema": "policy-studio/artifact-impact-replay-source/v1",
              "sources": [{"path": n, "sha256": h(n)} for n in ("replay.go", "replay_identity.go", "replay_files.go")],
              "comparison": comparison, "verifier_sha256": verifier}
    renderer = {"schema": "policy-studio/artifact-impact-explain-source/v1",
                "sources": [{"path": n, "sha256": h(n)} for n in ("explain.go", "explain_files.go", "explain_identity.go", "explain.html")],
                "replay": replay, "cli_argument_handling_bound": False, "renderer_sha256": ""}
    renderer["renderer_sha256"] = hash_value(renderer)
    return comparison, replay, renderer


def material_presence(binary, source):
    selected = set()
    packages = ("artifactimpact", "artifactpreflight", "artifactnumeric", "jsoninput", "policy", "completion", "machinerules")
    for name, raw in source.items():
        if not name.startswith(tuple("internal/" + p + "/" for p in packages)) or not name.endswith(".go") or name.endswith("_test.go"):
            continue
        prefix = name.rsplit("/", 1)[0] + "/"
        for line in raw.decode("utf-8", "strict").splitlines():
            if not line.startswith("//go:embed "):
                continue
            for item in line[11:].split():
                directory_glob = item.endswith("/*")
                item = item[:-2] if directory_glob else item
                require(old.safe_name(item), "EMBED_PATTERN")
                path = prefix + item
                found = {path} if path in source and not directory_glob else {p for p in source if p.startswith(path + "/")}
                require(bool(found), "EMBED_SOURCE")
                selected.update(found)
    require(bool(selected), "EMBED_ROSTER")
    require(all(source[n] and source[n] in binary for n in selected), "SOURCE_MATERIAL_ABSENT")
    return {"method": "source_material_presence/v1", "authenticated": False, "CLI_argument_handling_bound": False,
            "sources": [{"path": n, "bytes": len(source[n]), "sha256": digest(source[n])} for n in sorted(selected)]}


def verify_members(members, modes, ref, tree, source, source_modes):
    copies = {"try-demo.sh": "examples/artifact-int64-bounds/try-demo.sh", "notices/LICENSE": "LICENSE",
              "notices/Go-LICENSE": "licenses/Go-LICENSE", "notices/LICENSE-REA": "internal/machinerules/assets/LICENSE-REA"}
    copies.update({"seeds/" + n: "examples/artifact-int64-bounds/" + n for n in SEEDS})
    copies.update({"docs/" + n: "docs/" + n for n in DOCS})
    roster = set(copies) | {"bin/policy-impact", "target.txt", "buildinfo.txt", "manifest.json", "SHA256SUMS", "notices/NOTICE.md"} | {"source/" + n for n in source}
    require(set(members) == set(modes) == roster, "KIT_ROSTER")
    expected_modes = {n: 0o644 for n in roster}
    expected_modes.update({"bin/policy-impact": 0o755, "try-demo.sh": 0o755})
    expected_modes.update({"source/" + n: m for n, m in source_modes.items()})
    require(modes == expected_modes, "KIT_MODES")
    require(all(members[n] == source[p] for n, p in copies.items()), "KIT_COPIED_SOURCE")
    require(all(members["source/" + n] == b for n, b in source.items()), "KIT_FULL_SOURCE")
    require(all(digest(members["seeds/" + n]) == s for n, s in zip(SEEDS, SEED_SHA)), "KIT_FROZEN_SEEDS")
    checksums = "".join(digest(members[n]) + "  " + n + "\n" for n in sorted(roster) if n != "SHA256SUMS").encode()
    require(members["SHA256SUMS"] == checksums, "KIT_CHECKSUMS")
    target = members["target.txt"].decode("ascii")
    require(target in ("darwin/arm64\n", "linux/amd64\n"), "KIT_TARGET")
    target = target.strip()
    binary = members["bin/policy-impact"]
    build = old.build_record(binary, members["buildinfo.txt"], target)
    row = lambda n, b, m: {"path": n, "mode": format(m, "04o"), "bytes": len(b), "sha256": digest(b)}
    expected = {"schema": "policy-impact-kit/v2", "target": target,
                "source": {"commit": ref, "tree": tree, "tracked_files": [row(n, source[n], source_modes[n]) for n in sorted(source)]},
                "binary": {"bytes": len(binary), "sha256": digest(binary), "build": build},
                "payload": [row(n, members[n], modes[n]) for n in sorted(roster) if n not in ("manifest.json", "SHA256SUMS")],
                "assembly": {"copy_only": True, "product_calls": 0, "builds": 0, "network_calls": 0,
                             "build_revision_is_package_source_commit": build["settings"]["vcs.revision"] == ref,
                             "binary_source_linkage": "Package snapshot and embedded source identities must be reviewed independently; VCS metadata is preserved, not rewritten."},
                "scope": "Experimental finite local simulation and unsigned same-implementation historical replay; no current execution grant or publisher authentication.",
                "limitations": {"macos_developer_id_or_notarization_claimed": False, "download_quarantine_tested": False,
                                "minimum_macos_runtime_verified": False, "portable_historical_replay": False, "binary_was_rebuilt_during_assembly": False},
                "profile": "artifact-bounds/v1", "binary_source_bindings": material_presence(binary, source)}
    require(exact(strict_json(members["manifest.json"]), expected), "KIT_MANIFEST")
    notice = members["notices/NOTICE.md"].decode("utf-8")
    require(all(s in notice for s in ("Google does not endorse", "Dirty", "notarization", "quarantine", "issuer", "MIT", "BSD", "musl", "private HTML")), "KIT_NOTICE")
    identities(source, target)  # Source/compiler/activity token binding before any optional demo.
    return expected


def summaries(replay, renderer):
    before = {"would_admit": True, "reason": "ADMITTED", "counts": counts((6, 6, 0))}
    after = {"would_admit": False, "reason": "EVIDENCE_REJECTED", "counts": counts((6, 5, 1))}
    detail = {"direction": "newly_denied", "before": before, "after": after, "added_claims": 0, "removed_claims": 0,
              "changed_claims": 1, "claim_order_changed": False, "recipe_configuration_changed": True,
              "approval_budget_changed": False, "approval_checks_changed": False}
    compare = {"schema": "policy-studio/artifact-impact-summary/v1", "status": "compared", "code": "COMPARISON_SAVED",
               "simulation": True, "report_saved": True, **detail}
    replay_summary = {"schema": "policy-studio/artifact-impact-replay-summary/v1", "status": "verified", "code": "HISTORICAL_COMPARISON_MATCH",
                      "historical": True, "simulation": True, "read_only": True, "authenticated_server_state": False,
                      "committed": False, "target_effects_executed": False, "current_artifact_reads": 0, **detail,
                      "verifier_sha256": replay["verifier_sha256"]}
    explain = {"schema": "policy-studio/artifact-impact-explain-summary/v1", "status": "saved", "code": "HISTORICAL_EXPLANATION_SAVED",
               "historical": True, "simulation": True, "read_only": False, "authenticated_server_state": False,
               "committed": False, "target_effects_executed": False, "current_artifact_reads": 0, "local_file_write_declared": True,
               "output_saved": True, "direction": "newly_denied", "before": before, "after": after,
               "verifier_sha256": replay["verifier_sha256"], "renderer_sha256": renderer["renderer_sha256"]}
    return compare, replay_summary, explain


def expected_side(name, policy, case, inputs, identity, artifact, now):
    after = name == "after"
    context = {"domain": "policy-studio/artifact-impact-simulation-context/v1", "side": name, "case": case,
               "inputs": inputs, "policy": policy, "implementation": identity}
    binding = hash_value(context)
    version = hash_value({"domain": "policy-studio/artifact-impact-simulation-policy/v1", "policy": policy, "case": case, "implementation": identity})
    producer = {"schema": "policy-studio/artifact-preflight/v2", "producer_id": "flat-json/v2", "identity": identity["producer"],
                "recipe_sha256": hash_value(policy["recipe"]), "expected_sha256": "sha256:" + SEED_SHA[1], "context_digest": binding,
                "observation_unix": now, "acquisition_status": "read_success", "artifact_base64": base64.b64encode(artifact).decode(),
                "actual_sha256": "sha256:" + SEED_SHA[1], "byte_count": 157, "observed_size": 157,
                "digest_ok": True, "schema_ok": True, "types_ok": True, "artifact_reason": "ARTIFACT_VERIFIED", "observations": []}
    base_digest = hash_value({"domain": "policy-studio/artifact-observation-base/v1", "report": producer})
    statuses = ("pass", "pass", "pass", "fail" if after else "pass", "pass", "pass")
    reasons = ("FIELD_EQUALS", "FIELD_EQUALS", "BOUND_MATCH", "BOUND_MISMATCH" if after else "BOUND_MATCH", "FIELD_EQUALS", "FIELD_EQUALS")
    actuals = ("prepare_export", "internal", "501", "501", "true", "jsonl")
    proofs = {2: GTE_ZERO, 3: LTE_500 if after else LTE_1000}
    evidence, records = [], []
    for i, claim in enumerate(policy["recipe"]["claims"]):
        require(claim["id"] == CLAIMS[i], "POLICY_CLAIM_ORDER")
        observation = {"claim_id": claim["id"], "verifier": claim["verifier"], "field": claim["field"], "expected": claim["expected"],
                       "actual": actuals[i], "status": statuses[i], "reason": reasons[i], "evidence_id": ""}
        if i in proofs:
            observation["native_proof"] = {**proofs[i], "bindings": identity["producer"]["numeric_bindings"]}
        observation["evidence_id"] = "ev_" + hash_value({"domain": "policy-studio/artifact-claim/v1", "base_sha256": base_digest, "observation": observation})[7:]
        producer["observations"].append(observation)
        failed = after and i == 3
        facts = {"actual_authority": "live-observation", "required_authority": "live-observation", "status": statuses[i], "confidence": "observed",
                 "provider_verified": True, "observed_binding": binding, "required_binding": binding, "observed_artifact": "sha256:" + SEED_SHA[1],
                 "required_artifact": "sha256:" + SEED_SHA[1], "observed_policy": version, "required_policy": version, "observed_at_unix": now,
                 "now_unix": now, "max_age_seconds": 60, "expires_at_unix": 4102444800}
        decision = {"admissible": not failed, "reason": "EVIDENCE_INCOMPLETE" if failed else "ADMISSIBLE", "provider_ok": True,
                    "evidence_ok": not failed, "authority_ok": True, "binding_ok": True, "artifact_ok": True, "policy_ok": True,
                    "freshness_ok": True, "deadline_ok": True}
        evidence.append({"claim_id": claim["id"], "facts": facts, "decision": decision})
        records.append({"claim_id": claim["id"], "status": statuses[i], "evidence_ids": [observation["evidence_id"]]})
    cp = {"schema": "policy-studio/completion-policy/v1", "policy_id": policy["id"], "revision": policy["revision"], "required_claims": list(CLAIMS)}
    binding_cp = dict(identity["completion"]); binding_cp["policy_sha256"] = hash_value(cp)
    rows, complete = (COUNTS_AFTER, COMPLETE_AFTER) if after else (COUNTS_BEFORE, COMPLETE_BEFORE)
    steps = [{"index": i, "counts_before": counts(rows[i]), "status": statuses[i],
              "decision": {**counts(rows[i + 1]), "valid": True, "complete": complete[i], "reason": "ACCUMULATED"}} for i in range(6)]
    completion = {"schema": "policy-studio/completion-report/v1", "policy": cp,
                  "input": {"schema": "policy-studio/completion-input/v1", "request_id": "req_" + binding[7:], "records": records},
                  "steps": steps, "summary": {**counts(rows[6]), "valid": True, "complete": not after, "reason": "NON_PASS_RESULTS" if after else "ALL_PASS"},
                  "coverage": {"required_count": 6, "matched_count": 6, "unexpected_count": 0, "observed_count": 6}, "missing_claims": [], "unexpected_claims": [],
                  "readiness": {"ready": not after, "reason": "NON_PASS_RESULTS" if after else "READY", "counts_ok": True, "coverage_ok": True, "summary_ok": True, "all_pass_ok": not after},
                  "bindings": binding_cp}
    effects = {"admissible": True, "reason": "WITHIN_EFFECT_BUDGET", **{k: True for k in ("target_ok", "session_ok", "filesystem_ok", "process_ok", "network_ok", "ui_ok", "discard_ok", "foreign_code_ok", "device_ok", "idempotency_ok")}}
    tool = lambda target, session, write, idem: dict(zip(("mutatesTarget", "mutatesSession", "writesFilesystem", "launchesProcess", "accessesNetwork", "changesUiState", "mayDiscardData", "executesForeignCode", "mutatesDevice", "idempotent"), (target, session, write, False, False, False, False, False, False, idem)))
    return {"context": context, "context_sha256": binding, "simulation_policy_version": version, "producer": producer, "evidence": evidence, "completion": completion,
            "proposed_approval": {"facts": tool(True, True, True, True), "budget": policy["approval_budget"], "decision": effects},
            "proposed_control_plane": {"facts": tool(False, True, True, True), "budget": policy["control_plane_budget"], "decision": effects},
            "admission_facts": {"provenance_ok": True, "base_policy_approved": True, "required_count": 6, "observed_count": 6,
                                "admissible_evidence_count": 5 if after else 6, "completion_ready": not after, "approval_effect_admissible": True, "control_plane_effect_admissible": True},
            "decision": {"admitted": not after, "reason": "EVIDENCE_REJECTED" if after else "ADMITTED", "counts_ok": True, "provenance_ok": True,
                         "base_policy_ok": True, "evidence_ok": not after, "completion_ok": not after, "approval_effect_ok": True, "control_plane_effect_ok": True},
            "would_admit": not after, "reason": "EVIDENCE_REJECTED" if after else "ADMITTED"}


def check_report(raw, members, source, target, work):
    actual = strict_json(raw)
    require(type(actual) is dict and type(actual.get("observation_unix")) is int and 0 < actual["observation_unix"] < 4102444800, "REPORT_CLOCK")
    identity, replay, renderer = identities(source, target)
    case_raw = members["seeds/" + SEEDS[0]].replace(b"/replace-with-your-private-directory/artifact-row-501.json", (str(work) + "/artifact-row-501.json").encode())
    input_raw = [case_raw, members["seeds/" + SEEDS[2]], members["seeds/" + SEEDS[3]]]
    case, before, after = map(strict_json, input_raw)
    inputs = {key: {"raw_sha256": "sha256:" + digest(b), "semantic_sha256": hash_value(strict_json(b))} for key, b in zip(("case", "before", "after"), input_raw)}
    created = actual["base_receipt"]["created_at"]
    require(type(created) is str and bool(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{0,8}[1-9])?Z", created)), "BASE_CLOCK_FORMAT")
    datetime.datetime.strptime(created.split(".")[0].removesuffix("Z"), "%Y-%m-%dT%H:%M:%S")
    approved = {"approved": True, "reason": "APPROVED", "amount_ok": True, "team_ok": True, "reviewer_ok": True, "self_ok": True, "submitted_ok": True}
    base = {"schema": "policy-studio/execution/v1", "id": "", "created_at": created,
            "source_sha256": identity["base"]["source_sha256"], "generated_sha256": identity["base"]["generated_sha256"], "compiler_source_sha": identity["base"]["compiler_source_sha"],
            "input": {"request": case["request"], "reviewer": {k: case["principal"][k] for k in ("key", "team", "active")}, "before": case["base_rules"], "after": case["base_rules"]},
            "result": {"before": approved, "after": approved, "change": {"changed": False, "direction": "UNCHANGED", "reason_changed": False}}, "scope": BASE_SCOPE}
    base["id"] = hash_value(base)
    expected = {"schema": "policy-studio/artifact-policy-comparison/v1", "id": "", "simulation": True,
                "authenticated_server_state": False, "committed": False, "target_effects_executed": False,
                "observation_unix": actual["observation_unix"], "inputs": inputs, "implementation": identity,
                "permission": {"eligible": True, "reason": "PROPOSED_PERMISSION_ELIGIBLE", "modeled_http_status": 200}, "base_receipt": base,
                "before": expected_side("before", before, case, inputs, identity, members["seeds/" + SEEDS[1]], actual["observation_unix"]),
                "after": expected_side("after", after, case, inputs, identity, members["seeds/" + SEEDS[1]], actual["observation_unix"]),
                "delta": {"direction": "newly_denied", "added": [], "removed": [], "changed": [{"claim_id": "row_limit_at_most", "predicate_changed": True,
                         "artifact_schema_changed": False, "field_type_changed": False, "status_changed": True, "reason_changed": True, "actual_changed": False, "evidence_decision_changed": True}],
                         "policy_identity_changed": True, "recipe_configuration_changed": True, "claim_order_changed": False, "approval_budget_changed": False,
                         "approval_checks_changed": False, "control_plane_checks_changed": False},
                "audit": {"schema": "policy-studio/artifact-impact-audit/v1", "artifact_read_attempts": 1, "acquisition_status": "read_success", "input_files_read": 3,
                          "private_report_reserved": True, "private_report_write_planned": True,
                          "effects": dict(zip(("mutatesTarget", "mutatesSession", "writesFilesystem", "launchesProcess", "accessesNetwork", "changesUiState", "mayDiscardData", "executesForeignCode", "mutatesDevice", "idempotent"), (False, False, True, False, False, False, False, False, False, False)))},
                "scope": REPORT_SCOPE}
    expected["id"] = hash_value(expected)
    require(exact(actual, expected), "WHOLE_TYPED_REPORT_LITERAL_OR_BINDING")
    return expected, replay, renderer, case_raw


class Explanation(HTMLParser):
    def __init__(self):
        super().__init__(); self.blocks = []; self.buffer = []; self.pre = False; self.absent = 0; self.claims = []; self.heading = False; self.head = []; self.text = []; self.sections = []; self.details = 0
        self.section = ""; self.table = None; self.caption = None; self.row = None; self.cell = None; self.claim_tables = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        require(tag not in ("script", "form", "button", "iframe", "img", "link", "input") and not any(k.lower().startswith("on") for k in a), "HTML_ACTIVE_CONTENT")
        require(not any(k in ("src", "href", "action", "srcdoc") for k in a), "HTML_REMOTE_OR_ACTION")
        if tag == "section": self.section = a.get("id"); self.sections.append(self.section)
        if tag == "table": self.table = {"section": self.section, "caption": "", "rows": []}
        if tag == "caption" and self.table is not None: self.caption = []
        if tag == "tr" and self.table is not None: self.row = []
        if tag in ("td", "th") and self.row is not None: self.cell = []
        if tag == "details": require("open" not in a, "HTML_DISCLOSURE_DEFAULT"); self.details += 1
        if tag == "pre": self.pre = True; self.buffer = []
        if tag == "h4": self.heading = True; self.head = []
    def handle_data(self, data):
        self.text.append(data)
        if self.pre: self.buffer.append(data)
        if self.heading: self.head.append(data)
        if self.caption is not None: self.caption.append(data)
        if self.cell is not None: self.cell.append(data)
        if data.strip() == "Not executed": self.absent += 1
    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None:
            self.row.append("".join(self.cell)); self.cell = None
        if tag == "tr" and self.row is not None:
            self.table["rows"].append(self.row); self.row = None
        if tag == "caption" and self.caption is not None:
            self.table["caption"] = "".join(self.caption); self.caption = None
        if tag == "table" and self.table is not None:
            if self.table["caption"] == "Claims in configured required order": self.claim_tables.append(self.table)
            self.table = None
        if tag == "section": self.section = ""
        if tag == "pre": self.pre = False; self.blocks.append(strict_json("".join(self.buffer).encode()))
        if tag == "h4":
            self.heading = False; h = "".join(self.head)
            if h.startswith("Claim evidence: "): self.claims.append(h[len("Claim evidence: "):])


def claim_table_rows(report):
    tables = []
    boolean = lambda value: "true" if value else "false"
    for name in ("before", "after"):
        side = report[name]
        rows = [CLAIM_HEADERS]
        for observation, evidence in zip(side["producer"]["observations"], side["evidence"]):
            rows.append([observation["claim_id"], "true", observation["verifier"], observation["field"], observation["expected"],
                         observation["status"], observation["actual"], observation["reason"], boolean(evidence["decision"]["admissible"]), evidence["decision"]["reason"]])
        tables.append({"section": "side-" + name, "caption": "Claims in configured required order", "rows": rows})
    return tables


def check_claim_tables(actual, expected):
    require(exact(actual, expected), "HTML_VISIBLE_REQUIRED_CLAIM_CELLS")


def check_html(raw, report, renderer):
    page = Explanation(); page.feed(raw.decode("utf-8", "strict")); page.close()
    require(page.sections == ["comparison", "side-before", "side-after", "provenance"] and page.claims == list(CLAIMS) * 2 and page.absent == 8, "HTML_ORDERED_CLAIMS")
    check_claim_tables(page.claim_tables, claim_table_rows(report))
    require(page.details == 25 and b"default-src 'none'" in raw, "HTML_CSP_OR_DETAILS")
    expected = [report["base_receipt"]["result"][k] for k in ("before", "after", "change")] + [report["delta"]]
    for name in ("before", "after"):
        s = report[name]; producer = s["producer"]
        expected += [s["decision"], s["admission_facts"], {"schema": producer["schema"], "producer_id": producer["producer_id"], "artifact_schema": s["context"]["policy"]["recipe"]["artifact_schema"],
                     **{k: producer[k] for k in ("acquisition_status", "byte_count", "observed_size", "digest_ok", "schema_ok", "types_ok", "artifact_reason")}},
                     s["completion"]["summary"], s["completion"]["coverage"], s["completion"]["readiness"], *s["completion"]["steps"]]
        for observation, evidence in zip(producer["observations"], s["evidence"]):
            expected += [evidence["facts"], evidence["decision"]]
            if "native_proof" in observation: expected.append(observation["native_proof"])
        expected += [s["proposed_approval"], s["proposed_control_plane"]]
    require(exact(page.blocks, expected), "HTML_FULL_STAGE_AND_NUMERIC_PROOFS")
    text = "".join(page.text)
    require(all(v in text for v in (renderer["renderer_sha256"], renderer["replay"]["verifier_sha256"], hash_value(report["implementation"]), str(report["observation_unix"]), "newly_denied")), "HTML_SOURCE_OR_HISTORICAL_CLOCK")
    require(not any(v in text for v in (report["id"], report["before"]["context"]["case"]["artifact"]["path"], report["before"]["context"]["case"]["principal"]["key"], report["before"]["context"]["case"]["request"]["key"])), "HTML_PRIVATE_IDENTIFIER")
    return {"claims": 12, "ordered_completion_steps": 12, "numeric_proofs": 4, "native_proof_shape": "3 facts/5 outputs/12 bindings", "not_executed": 8, "JSON_blocks": len(page.blocks)}


def static_failures(members, modes, ref, tree, source, source_modes):
    result = []
    for label, path, value in (("seed", "seeds/" + SEEDS[1], b"{}"), ("binary", "bin/policy-impact", members["bin/policy-impact"] + b"changed"),
                               ("buildinfo", "buildinfo.txt", b"invalid"), ("source", "source/go.mod", b"invalid"), ("profile", "manifest.json", members["manifest.json"].replace(b"artifact-bounds/v1", b"artifact-bounds/v0"))):
        changed = dict(members); changed[path] = value
        try: verify_members(changed, modes, ref, tree, source, source_modes)
        except (Rejected, ValueError) as error: result.append({"case": label, "rejected": True, "code": str(error) if isinstance(error, Rejected) else "INVALID_METADATA", "product_calls": 0})
        else: raise Rejected("STATIC_MUTATION_ACCEPTED")
    return result


def self_test():
    result = []
    def archive(entries):
        buf = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(buf, "w") as z:
                for path, mode in entries:
                    i = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0)); i.create_system = 3; i.external_attr = mode << 16; i.compress_type = zipfile.ZIP_DEFLATED
                    z.writestr(i, b"x")
        return buf.getvalue()
    prefix = "policy-impact-kit/"; regular = stat.S_IFREG | 0o644
    for label, entries in (("traversal", [(prefix + "../x", regular)]), ("duplicate", [(prefix + "x", regular)] * 2),
                           ("symlink", [(prefix + "x", stat.S_IFLNK | 0o777)]), ("FIFO", [(prefix + "x", stat.S_IFIFO | 0o644)]),
                           ("unsorted", [(prefix + "z", regular), (prefix + "a", regular)])):
        try: old.zip_members(archive(entries))
        except Rejected as e: result.append({"case": label, "code": str(e), "product_calls": 0})
        else: raise Rejected("STATIC_INVALID_ZIP_ACCEPTED")
    oversized = bytearray(archive([(prefix + "bin/policy-impact", stat.S_IFREG | 0o755)])); central = oversized.index(b"PK\x01\x02")
    struct.pack_into("<I", oversized, central + 24, (64 << 20) + 1)
    try: old.zip_members(oversized)
    except Rejected as e: result.append({"case": "declared_oversized", "code": str(e), "product_calls": 0})
    else: raise Rejected("STATIC_OVERSIZED_ACCEPTED")
    for label, raw in (("duplicate_JSON", b'{"profile":"x","profile":"y"}'), ("nonfinite_JSON", b'{"x":NaN}')):
        try: strict_json(raw)
        except Rejected as e: result.append({"case": label, "code": str(e), "product_calls": 0})
        else: raise Rejected("STATIC_INVALID_JSON_ACCEPTED")
    require(not exact({"matched": True}, {"matched": 1}), "STATIC_BOOL_TYPE")
    # A tiny handwritten display fixture checks the new acceptance boundary;
    # it neither calls a renderer nor imports any closed HTML/native corpus.
    cell_row = ["row_limit_at_most", "true", "field_int64_lte/v1", "row_limit", "500", "fail", "501", "BOUND_MISMATCH", "false", "EVIDENCE_INCOMPLETE"]
    markup = '<section id="side-after"><table><caption>Claims in configured required order</caption><tr>' + ''.join('<th>' + x + '</th>' for x in CLAIM_HEADERS) + '</tr><tr>' + ''.join('<td>' + x + '</td>' for x in cell_row) + '</tr></table></section>'
    expected_table = [{"section": "side-after", "caption": "Claims in configured required order", "rows": [CLAIM_HEADERS, cell_row]}]
    parsed = Explanation(); parsed.feed(markup); parsed.close()
    check_claim_tables(parsed.claim_tables, expected_table)
    for label, original, replacement in (("visible_bound_cell", "<td>500</td>", "<td>1000</td>"), ("visible_status_cell", "<td>fail</td>", "<td>pass</td>")):
        changed = Explanation(); changed.feed(markup.replace(original, replacement, 1)); changed.close()
        try: check_claim_tables(changed.claim_tables, expected_table)
        except Rejected as e: result.append({"case": label, "code": str(e), "product_calls": 0})
        else: raise Rejected("STATIC_WRONG_VISIBLE_CELL_ACCEPTED")
    return result


def run_demo(members, modes, source, target, trace):
    host = {("Darwin", "arm64"): "darwin/arm64", ("Linux", "x86_64"): "linux/amd64"}.get((platform.system(), platform.machine()))
    require(host == target, "DEMO_HOST")
    extraction = Path(tempfile.mkdtemp(prefix="gooo-policy-impact-bounds-kit-verify-", dir="/tmp")).resolve(); extraction.chmod(0o700)
    trace["extraction_directory"] = str(extraction)
    root = extraction / "policy-impact-kit"; root.mkdir(mode=0o700)
    for n in sorted(members):
        f = root / n; f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with f.open("xb") as stream: os.fchmod(stream.fileno(), modes[n]); stream.write(members[n])
    require(all(old.read_file(root / n, old.MAX_ARCHIVE) == b for n, b in members.items()), "EXTRACTION_BYTES")
    start = int(time.time()); trace["spawn_attempted"] = True
    capture = old.capture_demo([str(root / "try-demo.sh")], root, trace)
    trace.update({"exit_code": capture["exit_code"], "stdout_complete": capture["stdout_complete"], "stderr_complete": capture["stderr_complete"]})
    try:
        partial = strict_json(capture["stdout"]); work_name = partial.get("work_directory", "") if isinstance(partial, dict) else ""
        if re.fullmatch(WORK_PATTERN, work_name):
            trace["private_work_directory"] = work_name
            calls = old.read_file(Path(work_name) / "product-calls.tsv", 8192, 0o600)
            trace["call_log_raw_base64"] = base64.b64encode(calls).decode()
            rows = [r.split("\t") for r in calls.decode().splitlines()]
            trace.update(product_calls_known=True, product_calls=sum(len(r) == 5 and r[3] == "started" for r in rows), completed_product_calls=sum(len(r) == 5 and r[3] == "completed" for r in rows))
    except (Rejected, OSError, ValueError, TypeError, UnicodeError): pass
    require(capture["stdout_complete"] and capture["stderr_complete"] and capture["exit_code"] == 0 and capture["stderr"] == b"", "DEMO_PROCESS_FAILED_OR_UNCERTAIN")
    result = strict_json(capture["stdout"])
    require(type(result) is dict and set(result) == {"schema", "status", "work_directory", "product_calls", "simulation"} and result["schema"] == "policy-impact-bounds-kit-demo/v1" and result["status"] == "completed" and exact(result["product_calls"], 3) and exact(result["simulation"], True), "DEMO_SUMMARY")
    work = Path(result["work_directory"])
    require(re.fullmatch(WORK_PATTERN, str(work)) and work.resolve() == work and stat.S_ISDIR(work.lstat().st_mode) and stat.S_IMODE(work.stat().st_mode) == 0o700, "DEMO_PRIVATE_WORK")
    wanted = "".join(f"{i}\t{action}\tnewly_denied\t{phase}\t{rc}\n" for i, action in ((1, "compare"), (2, "replay"), (3, "explain")) for phase, rc in (("started", "-"), ("completed", "0")))
    require(old.read_file(work / "product-calls.tsv", 8192, 0o600).decode() == wanted, "DEMO_EXACT_THREE_CALLS")
    require(old.read_file(work / "inputs.deleted", 8192, 0o600) == ("\n".join(SEEDS) + "\n").encode() and all(not (work / n).exists() and not (work / n).is_symlink() for n in SEEDS), "DEMO_FOUR_INPUTS_DELETED")
    digests = {}
    for line in old.read_file(work / "digests.tsv", 8192, 0o600).decode().splitlines():
        pair = line.split("\t"); require(len(pair) == 2 and pair[0] not in digests and re.fullmatch(r"[0-9a-f]{64}", pair[1]), "DEMO_DIGESTS"); digests[pair[0]] = pair[1]
    report_raw = old.read_file(work / "comparison.report.json", FINITE_FILE, 0o600)
    html = old.read_file(work / "explanation.html", FINITE_FILE, 0o600)
    trace.update(report_raw_base64=base64.b64encode(report_raw).decode(), HTML_raw_base64=base64.b64encode(html).decode(), report_mode="0600", HTML_mode="0600", digests=digests)
    report, replay, renderer, case_raw = check_report(report_raw, members, source, target, work)
    require(start - 1 <= report["observation_unix"] <= int(time.time()), "DEMO_OBSERVATION_TIME")
    expected_summaries = summaries(replay, renderer); trace["product_summaries"] = []
    for name, expected in zip(("01-compare", "02-replay", "03-explain"), expected_summaries):
        raw = old.read_file(work / (name + ".summary.json"), 8192, 0o600)
        trace["product_summaries"].append({"name": name, "raw_base64": base64.b64encode(raw).decode()})
        require(exact(strict_json(raw), expected) and digests.get(name + ".summary") == digest(raw), "DEMO_FULL_SUMMARY_LITERAL")
        require(old.read_file(work / (name + ".stderr"), 8192, 0o600) == b"", "DEMO_PRODUCT_STDERR")
    trace["HTML_checks"] = check_html(html, report, renderer)
    expected_digests = {"binary_before": digest(members["bin/policy-impact"]), "binary_after": digest(members["bin/policy-impact"]),
                        **{"input_" + n: digest(case_raw if i == 0 else members["seeds/" + n]) for i, n in enumerate(SEEDS)},
                        **{k: digest(report_raw) for k in ("report_before_replay", "report_after_replay", "report_before_explain", "report_after_explain")},
                        "explanation_html": digest(html),
                        **{n["name"] + ".summary": digest(base64.b64decode(n["raw_base64"])) for n in trace["product_summaries"]}}
    require(exact(digests, expected_digests), "DEMO_INPUT_REPORT_BINARY_DIGEST_ROSTER")
    require(all(old.read_file(root / n, old.MAX_ARCHIVE, modes[n]) == b for n, b in members.items()), "DEMO_ALL_KIT_BYTES_AND_MODES_UNCHANGED")
    trace.update(status="accepted", product_calls=3, completed_product_calls=3, product_calls_known=True, compare_calls=1, replay_calls=1, explain_calls=1,
                 historical_observation_unix=report["observation_unix"], four_inputs_deleted=True,
                 scope="Three finite CLI calls, not three native calls or a general issuer/security/portable-host proof.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive"); parser.add_argument("--source-ref"); parser.add_argument("--output")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--run-demo", action="store_true"); parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    def interrupted(_number, _frame): raise Rejected("VERIFICATION_INTERRUPTED")
    for number in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)): signal.signal(number, interrupted)
    if args.self_test:
        if args.archive or args.source_ref or args.output or args.run_demo: parser.error("--self-test is standalone")
        try:
            checks = self_test(); print(json.dumps({"schema": "policy-impact-bounds-kit-self-test/v1", "status": "accepted", "checks": checks, "product_calls": 0}, separators=(",", ":"))); return 0
        except Exception:
            print('{"schema":"policy-impact-bounds-kit-self-test/v1","status":"error","code":"STATIC_CHECK_FAILED","product_calls":0}'); return 2
    if not (args.archive and args.source_ref and args.output): parser.error("--archive, --source-ref and --output are required")
    result = {"schema": "policy-impact-bounds-kit-verification/v1", "status": "pending", "product_calls": 0, "builds": 0, "network_calls": 0}; output_fd = None
    try:
        output_fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600); os.fchmod(output_fd, 0o600)
        raw = old.read_file(args.archive, old.MAX_ARCHIVE)
        tree, source, source_modes = old.committed_source(Path(args.repo).resolve(), args.source_ref)
        members, modes = old.zip_members(raw)
        manifest = verify_members(members, modes, args.source_ref, tree, source, source_modes)
        result.update(archive_bytes=len(raw), archive_sha256=digest(raw), source_commit=args.source_ref, source_tree=tree, target=manifest["target"], member_count=len(members), tracked_source_files=len(source),
                      manifest_sha256=digest(members["manifest.json"]), binary=manifest["binary"], source_material_presence=manifest["binary_source_bindings"],
                      static_failure_checks=static_failures(members, modes, args.source_ref, tree, source, source_modes),
                      oracle_method="Pre-run handwritten row501 native/stage/summary literals; dynamic clock/path and identities bound from committed bytes, never observed predicate answers.")
        if args.run_demo:
            result["demo"] = {"status": "pending", "spawn_attempted": False, "spawned": False, "product_calls": 0, "completed_product_calls": 0, "product_calls_known": True}
            run_demo(members, modes, source, manifest["target"], result["demo"]); result["product_calls"] = result["demo"]["product_calls"]
        else: result["demo"] = {"status": "not_run", "product_calls": 0}
        require(old.read_file(args.archive, old.MAX_ARCHIVE) == raw, "ARCHIVE_CHANGED")
        require(old.committed_source(Path(args.repo).resolve(), args.source_ref) == (tree, source, source_modes), "SOURCE_CHANGED")
        result["status"] = "accepted"
    except Exception as error:
        result.update(status="error", code=str(error) if isinstance(error, Rejected) else "VERIFICATION_FAILED")
        if "demo" in result:
            result["demo"]["status"] = "error"; result["product_calls"] = result["demo"].get("product_calls")
    finally:
        result["product_execution_may_have_started"] = result.get("demo", {}).get("spawned", False)
        if output_fd is not None:
            try:
                with os.fdopen(output_fd, "wb") as f:
                    output_fd = None
                    saved = (json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
                    require(len(saved) <= 16 << 20, "PROOF_OUTPUT_BOUNDS"); f.write(saved); f.flush(); os.fsync(f.fileno())
            except (Rejected, OSError, ValueError):
                result.update(status="error", code="PROOF_WRITE_FAILED")
            finally:
                if output_fd is not None: os.close(output_fd)
    print(json.dumps({k: result[k] for k in ("schema", "status", "product_calls", "product_execution_may_have_started")} | ({"code": result["code"]} if "code" in result else {}), separators=(",", ":")))
    return 0 if result["status"] == "accepted" else 2


if __name__ == "__main__":
    sys.exit(main())
