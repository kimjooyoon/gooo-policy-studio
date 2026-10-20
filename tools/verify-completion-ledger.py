#!/usr/bin/env python3
"""Observe fixed completion fixtures through native Gooo and a built CLI.

Expectations are immutable, independently authored literals. This observer does
not create expectations from candidate rules and never invokes a target tool.
"""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT / "examples/completion-ledger"
spec = importlib.util.spec_from_file_location("evidence_receipts", PROJECT / "tools/verify-evidence-admission.py")
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)
require, sha, exact, read = receipts.require, receipts.sha, receipts.exact, receipts.read
strict_json, command = receipts.strict_json, receipts.command
PIN = "83928fa4538245abe33b08549da47f8cbdc50ed2"
UPSTREAM_PIN = "8fc2043eb8bcedbf34dce064f977e455438635d6"
UPSTREAM_SHA = "cb721d4422094f2b2051625de83b3981642c388b114f5ce26d4de48fd83a749b"
LICENSE_SHA = "798f9e4d18e49b30bf2f12696c8ced73dc4e1413da375a333d01281543a1ea8b"
SOURCE_SHA = "bb06ad147613baf79075cd91f982e4103bc72cc4613a76cab94b3ea4ce831f5d"
CATALOG_SHA = "197230266f97fbd5ccf22a4452d9691ba9bf3364102a2c6f732bbdbfb0462e23"
BOOKS = {
    "step-cases.json": (1025, "6dcb26e64ca8e27a44dd5823f04f6a1bfc496eee0d014432215263ac384cc8dc"),
    "finish-cases.json": (188, "d82141b4e67609ac23d76fb4c41256ebe704cf826d9f33472d2af451d9b6b08d"),
    "ready-cases.json": (4080, "b33a91a1ac4370718d4b61f460f3b8facd16172482558ba52e89f62c5f452fd3"),
    "host-cases.json": (803, "0f3a8449dc1f167d4a24c32b3603558ec43fe957f63aa12291869c8f797002c9"),
}
STATUSES = ["pass", "fail", "unsupported", "truncated", "unknown"]
COUNT_FIELDS = ["total"] + STATUSES
DECISION_FIELDS = COUNT_FIELDS + ["valid", "complete", "reason"]
READINESS_FIELDS = ["ready", "reason", "counts_ok", "coverage_ok", "summary_ok", "all_pass_ok"]
PREFIX = "gooo/completion-ledger:"
ENTRIES = {name: PREFIX + "Completion" + name.title() for name in ("step", "finish", "ready")}
REPORT_FIELDS = {"schema", "policy", "input", "steps", "summary", "coverage", "missing_claims", "unexpected_claims", "readiness"}


def encode(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def integer(value):
    return type(value) is int and -(1 << 63) <= value < (1 << 63)


def check_record(value, fields, integers=(), booleans=()):
    require(type(value) is dict and set(value) == set(fields), "fixture record field roster differs")
    require(all(integer(value[k]) for k in integers), "fixture Integer type or range differs")
    require(all(type(value[k]) is bool for k in booleans), "fixture Boolean type differs")
    require(all(type(value[k]) is str for k in set(fields) - set(integers) - set(booleans)), "fixture Text type differs")


def fixture_integrity():
    catalog_raw = (EXAMPLE / "cases/catalog.json").read_bytes()
    require(sha(catalog_raw) == "sha256:" + CATALOG_SHA, "independent catalog bytes differ")
    catalog = strict_json(catalog_raw)
    require(catalog["schema"] == "policy-studio/completion-fixture-catalog/v1" and
            catalog["status"] == "INDEPENDENT_EXPECTATION_AUTHORSHIP_NOT_NATIVE_ACCEPTANCE", "catalog status differs")
    for key in ("candidate_implementation_read", "generated_go_read", "host_implementation_read", "verifier_read",
                "actual_execution_output_read", "native_execution_performed", "build_or_test_performed", "network_performed"):
        require(catalog["authorship"][key] is False, "catalog independence declaration differs")
    require(sha((EXAMPLE / "completion.gooo").read_bytes()) == "sha256:" + SOURCE_SHA, "reviewed Gooo source differs")
    metadata = read(EXAMPLE / "upstream.json")
    require(metadata["commit"] == UPSTREAM_PIN, "upstream revision differs")
    for name, path, digest in (("source", "upstream/evidenceCompletionLedger.ts", UPSTREAM_SHA),
                               ("license", "LICENSE-REA", LICENSE_SHA)):
        raw = (EXAMPLE / path).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(metadata[name + "_sha256"] == digest and sha(raw) == "sha256:" + digest and
                metadata[name + "_bytes"] == len(raw) and metadata[name + "_git_blob_sha1"] == blob,
                "pinned upstream source/license byte binding differs")
    catalog_books = {item["file"]: item for item in catalog["books"]}
    require(len(catalog_books) == len(catalog["books"]) and set(catalog_books) == set(BOOKS), "catalog book roster differs")
    books = {}
    for name, (total, digest) in BOOKS.items():
        path = EXAMPLE / "cases" / name
        raw, declared = path.read_bytes(), catalog_books[name]
        document = strict_json(raw)
        require(set(document) == {"schema", "cases"} and type(document["cases"]) is list and
                len(document["cases"]) == total and declared["case_count"] == total and
                declared["byte_count"] == len(raw) and declared["sha256"] == digest and sha(raw) == "sha256:" + digest,
                "frozen fixture count, bytes or hash differs: " + name)
        schema = "policy-studio/completion-host-cases/v1" if name == "host-cases.json" else "gooo/body-composition-cases/v1"
        require(document["schema"] == declared["schema"] == schema, "fixture schema differs")
        books[name] = document["cases"]
    ids, indexed, families = set(), {name: set() for name in BOOKS}, {name: Counter() for name in BOOKS}
    for item in catalog["case_catalog"]:
        require(set(item) == {"book", "index", "id", "name", "family"}, "catalog item fields differ")
        name, index = item["book"], item["index"]
        require(name in books and type(index) is int and 0 <= index < len(books[name]) and
                index not in indexed[name] and item["id"] not in ids, "catalog index or ID is duplicate/invalid")
        indexed[name].add(index)
        ids.add(item["id"])
        families[name][item["family"]] += 1
    for name in BOOKS:
        require(indexed[name] == set(range(len(books[name]))) and dict(families[name]) == catalog_books[name]["families"],
                "catalog omitted or recategorized fixtures")
    for name in ("step", "finish", "ready"):
        entry = ENTRIES[name]
        keys = {entry} if name == "finish" else {entry + ".input0", entry + ".input1"}
        for case in books[name + "-cases.json"]:
            require(set(case) == {"inputs", "expected"} and set(case["inputs"]) == keys, "core fixture fields differ")
            if name == "ready":
                check_record(case["inputs"][entry + ".input0"], DECISION_FIELDS, COUNT_FIELDS, ["valid", "complete"])
                check_record(case["inputs"][entry + ".input1"], ["required_count", "matched_count", "unexpected_count", "observed_count"],
                             ["required_count", "matched_count", "unexpected_count", "observed_count"])
                check_record(case["expected"], READINESS_FIELDS, (), set(READINESS_FIELDS) - {"reason"})
            else:
                key = entry if name == "finish" else entry + ".input0"
                check_record(case["inputs"][key], COUNT_FIELDS, COUNT_FIELDS)
                if name == "step":
                    require(type(case["inputs"][entry + ".input1"]) is str, "step status fixture is not Text")
                check_record(case["expected"], DECISION_FIELDS, COUNT_FIELDS, ["valid", "complete"])
    host = books["host-cases.json"]
    for case in host:
        require(set(case) == {"policy", "input", "expected"} and set(case["expected"]) == {"exit_code", "report"} and
                type(case["expected"]["exit_code"]) is int and case["expected"]["exit_code"] in (0, 1) and
                set(case["expected"]["report"]) == REPORT_FIELDS and
                exact(case["expected"]["report"]["policy"], case["policy"]) and
                exact(case["expected"]["report"]["input"], case["input"]), "complete host fixture differs")
    sequences = [tuple(record["status"] for record in case["input"]["records"]) for case in host[:780]]
    domain = [row for length in range(1, 5) for row in itertools.product(STATUSES, repeat=length)]
    require(exact(sequences, domain), "complete ordered finite host status domain differs")
    contract = read(EXAMPLE / "contract.json")
    require(contract["compiler"]["revision"] == PIN and contract["package_path"] == "gooo/completion-ledger", "core contract identity differs")
    for name, entry in ENTRIES.items():
        workspace = read(EXAMPLE / (name + ".workspace.json"))
        require(workspace["entry"] == {"package_path": "gooo/completion-ledger", "activity": entry.split(":", 1)[1]} and
                workspace["packages"] == [{"path": "gooo/completion-ledger", "sources": ["completion.gooo"]}], "manifest entry/source roster differs")
    return books, {"catalog_sha256": sha(catalog_raw), "books": catalog["books"], "coverage": catalog["coverage"],
                   "scope": "Frozen independent expected literals; authorship declarations are not execution evidence."}


def original_reference(books, env, out):
    text = (EXAMPLE / "upstream/evidenceCompletionLedger.ts").read_bytes().decode("utf-8")
    start = text.index("const summarize = (")
    block = text[start:text.index("\n\nconst canonicalJson", start)]
    for before, after in (("records: readonly EvidenceCompletionRecord[],", "records,"),
                          ("): EvidenceCompletionLedger[\"summary\"] =>", ") =>"),
                          ("const counts: Record<EvidenceCompletionStatus, number> =", "const counts =")):
        require(block.count(before) == 1, "review changed original summarize extraction")
        block = block.replace(before, after, 1)
    rows, expectations, labels = [], [], []
    entry = ENTRIES["step"]
    states = set()
    for index, case in enumerate(books["step-cases.json"][:630]):
        counts = case["inputs"][entry + ".input0"]
        status = case["inputs"][entry + ".input1"]
        require(0 <= counts["total"] <= 4 and all(counts[k] >= 0 for k in STATUSES) and
                sum(counts[k] for k in STATUSES) == counts["total"] and status in STATUSES, "reachable step domain differs")
        states.add((tuple(counts[k] for k in COUNT_FIELDS), status))
        records = [{"status": name} for name in STATUSES for _ in range(counts[name])]
        rows.append(records + [{"status": status}])
        expectations.append({k: case["expected"][k] for k in COUNT_FIELDS + ["complete"]})
        labels.append({"book": "step-cases.json", "index": index, "extension": False})
    possible = {((total,) + values, status) for total in range(5)
                for values in itertools.product(range(total + 1), repeat=5) if sum(values) == total for status in STATUSES}
    require(states == possible and len(states) == 630, "step fixtures do not cover every reachable finite state/status")
    finish_states = set()
    for index, case in enumerate(books["finish-cases.json"][:126]):
        counts = case["inputs"][ENTRIES["finish"]]
        finish_states.add(tuple(counts[k] for k in COUNT_FIELDS))
        rows.append([{"status": name} for name in STATUSES for _ in range(counts[name])])
        expectations.append({k: case["expected"][k] for k in COUNT_FIELDS + ["complete"]})
        labels.append({"book": "finish-cases.json", "index": index, "extension": counts["total"] == 0})
    require(finish_states == {state for state, _ in possible} and len(finish_states) == 126, "finish finite domain differs")
    for index, case in enumerate(books["host-cases.json"]):
        rows.append(case["input"]["records"])
        summary = case["expected"]["report"]["summary"]
        expectations.append({k: summary[k] for k in COUNT_FIELDS + ["complete"]})
        labels.append({"book": "host-cases.json", "index": index, "extension": len(case["input"]["records"]) == 0})
    js = block + "\nconst rows=" + json.dumps(rows, ensure_ascii=True, separators=(",", ":")) + ";\n"
    js += "process.stdout.write(JSON.stringify(rows.map(summarize)));\n"
    result = subprocess.run(["node"], input=js.encode(), env=env, capture_output=True, timeout=30)
    require(result.returncode == 0 and not result.stderr, "isolated original summarize failed")
    actual = strict_json(result.stdout)
    require(type(actual) is list and len(actual) == len(expectations), "original summarize result roster differs")
    extension_count = 0
    for label, expected, observed in zip(labels, expectations, actual):
        if label["extension"]:
            require(exact(observed, {**{name: 0 for name in COUNT_FIELDS}, "complete": True}) and
                    exact(expected, {**{name: 0 for name in COUNT_FIELDS}, "complete": False}), "private/public empty boundary differs")
            extension_count += 1
        else:
            require(exact(observed, expected), "independent expected count/complete differs from original summarize: " + str(label))
    (out / "original-summarize.js").write_text(js)
    (out / "original-summarize-results.json").write_bytes(encode({"labels": labels, "results": actual}))
    return {"source_sha256": "sha256:" + UPSTREAM_SHA, "isolated_function_sha256": sha(js.encode()),
            "observations": len(actual), "matched_nonempty": len(actual) - extension_count,
            "public_empty_boundary_observations": extension_count, "reachable_counter_states": 126,
            "step_state_status_pairs": 630, "host_sequences_and_boundaries": 803,
            "scope": "Exact private original summarize with only three TypeScript annotations removed. Empty private complete=true is explicitly contrasted with public NO_RECORDS. No full ledger/RFC8785 or application compatibility claim."}


def native_batches(rows, entry, out, name):
    """Wrap fixed literal records for compiler transport; never change a value."""
    normalized = [{"inputs": row["inputs"], "expected": {entry: row["expected"]}} for row in rows]
    groups, current = [], []
    def raw(cases):
        return encode({"schema": "gooo/body-composition-cases/v1", "cases": cases})
    for case in normalized:
        require(len(raw([case])) <= 30000, "single fixture exceeds native JSON profile")
        if current and (len(current) >= 128 or len(raw(current + [case])) > 30000):
            groups.append(current)
            current = []
        current.append(case)
    if current:
        groups.append(current)
    require(exact([case for group in groups for case in group], normalized), "native transport changed fixture order or literals")
    paths = []
    for index, group in enumerate(groups):
        path = out / f"{name}-{index:03d}-cases.json"
        path.write_bytes(raw(group))
        paths.append(path)
    return paths


def mutation_checks(receipt, workspace, cases_file, entry, go_digest):
    def change_input(document):
        delivery = document["result"]["runtime"]["traces"][-1]["deliveries"][0]
        if entry in read(cases_file)["cases"][-1]["inputs"]:
            delivery["input"] = "different"
        else:
            delivery["inputs"][0]["value"] = "different"
    def change_index(document):
        traces = document["result"]["runtime"]["traces"]
        traces[-1]["case_index"] = 0 if len(traces) > 1 else -1
    mutations = {
        "boolean_integer_alias": lambda d: d["result"]["runtime"]["traces"][-1]["deliveries"][0].update(passed=1),
        "late_actual_result_changed": lambda d: d["result"]["runtime"]["traces"][-1]["deliveries"][0].update(actual=None),
        "late_input_changed": change_input,
        "duplicate_or_invalid_case_index": change_index,
        "different_producer": lambda d: d["result"]["runtime"].update(producer_source_sha="0" * 40),
        "unexpected_model_call": lambda d: d["result"]["runtime"].update(model_calls=1),
        "different_case_bytes": lambda d: d.update(cases_digest="sha256:" + "0" * 64),
        "missing_trace": lambda d: d["result"]["runtime"]["traces"].pop(),
        "exit_code_boolean_alias": lambda d: d["result"]["runtime"]["runs"][0].update(exit_code=False),
        "model_calls_boolean_alias": lambda d: d["result"]["runtime"].update(model_calls=False),
        "passed_count_float_alias": lambda d: d["result"]["runtime"].update(finite_passed=float(d["result"]["runtime"]["finite_passed"])),
        "duplicate_package": lambda d: d["result"]["program"]["workspace_image"]["packages"].append(copy.deepcopy(d["result"]["program"]["workspace_image"]["packages"][0])),
        "duplicate_source": lambda d: d["result"]["program"]["workspace_image"]["packages"][0]["sources"].append(copy.deepcopy(d["result"]["program"]["workspace_image"]["packages"][0]["sources"][0])),
        "changed_entry": lambda d: d["result"]["program"]["entry"].update(activity="different"),
    }
    for name, change in mutations.items():
        candidate = copy.deepcopy(receipt)
        change(candidate)
        require(not exact(candidate, receipt), "receipt mutation was a no-op: " + name)
        try:
            receipts.validate(candidate, workspace, cases_file, entry, PIN, go_digest, EXAMPLE)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("receipt mutation accepted: " + name)
    return list(mutations)


def observe_native(books, compiler, go, out, env, go_digest):
    records = []
    for name in ("step", "finish", "ready"):
        workspace, entry = EXAMPLE / (name + ".workspace.json"), ENTRIES[name]
        rows, offset, groups = books[name + "-cases.json"], 0, []
        for index, cases in enumerate(native_batches(rows, entry, out, name)):
            label = f"{name}-{index:03d}"
            receipt_path = out / (label + "-execution.json")
            raw = command([compiler, "package", "execute", "--json", "--go", go, "--cases", str(cases), str(workspace)], env)
            receipt_path.write_bytes(raw)
            receipt = strict_json(raw)
            runtime = receipts.validate(receipt, workspace, cases, entry, PIN, go_digest, EXAMPLE)
            replay_raw = command([compiler, "package", "replay", "--json", "--go", go, "--receipt", str(receipt_path), "--cases", str(cases), str(workspace)], env)
            (out / (label + "-replay.json")).write_bytes(replay_raw)
            replay = strict_json(replay_raw)
            second = receipts.validate(replay, workspace, cases, entry, PIN, go_digest, EXAMPLE)
            require(replay["replayed_from_sha256"] == sha(raw) and exact(runtime["traces"], second["traces"]) and
                    receipt["result"]["composition"]["source"] == replay["result"]["composition"]["source"] and
                    receipt["result"]["composition"]["driver_source"] == replay["result"]["composition"]["driver_source"] and
                    receipt["result"]["program"]["lowered_gooo_source"] == replay["result"]["program"]["lowered_gooo_source"],
                    "whole native completion replay differs")
            rejected = mutation_checks(receipt, workspace, cases, entry, go_digest)
            groups.append({"offset": offset, "cases": runtime["finite_total"], "passed": runtime["finite_passed"],
                           "whole_replay_equal": True, "native_execution_this_invocation": True,
                           "transport_cases_sha256": sha(cases.read_bytes()), "execution_sha256": sha(raw),
                           "replay_sha256": sha(replay_raw), "rejected_receipt_mutations": rejected})
            offset += runtime["finite_total"]
            print(json.dumps({"batch": label, "cases": runtime["finite_total"], "passed": runtime["finite_passed"], "whole_replay_equal": True}), flush=True)
        require(offset == len(rows), "not every independent core literal was observed")
        records.append({"name": name, "cases": len(rows), "passed": offset, "whole_replay_equal": True,
                        "original_cases_sha256": sha((EXAMPLE / "cases" / (name + "-cases.json")).read_bytes()),
                        "transport": "Only expected={entry:literal_record} wrapping; immutable inputs, expected values and order retained.", "batches": groups})
    return records


def source_bindings():
    directory = PROJECT / "internal/completion"
    source, generated, bridge, generation = [(directory / name).read_bytes() for name in
                                              ("source.gooo", "rules_generated.go", "bridge_generated.go", "generation.json")]
    require(source == (EXAMPLE / "completion.gooo").read_bytes(), "embedded source copy differs")
    require(generated == (directory / "generated.txt").read_bytes() and
            bridge == (directory / "bridge.txt").read_bytes(), "embedded generated/bridge copy differs from compiled Go")
    require((directory / "compiler-version.txt").read_text().strip() == PIN, "embedded compiler pin differs")
    record = strict_json(generation)
    require(record["schema"] == "policy-studio/completion-generation/v1", "generation schema differs")
    expected = {"source_sha256": sha(source), "generated_sha256": sha(generated), "bridge_sha256": sha(bridge),
                "generation_sha256": sha(generation), "compiler_source_sha": PIN}
    for field in ("source_sha256", "generated_sha256", "bridge_sha256"):
        require(record[field] == expected[field], "generation byte binding differs: " + field)
    compiler = record.get("compiler", record.get("producer", {}))
    require(compiler.get("compiler_source_sha") == PIN and compiler.get("source_status") == "CLEAN_VCS" and
            compiler.get("version") == "0.6.32-dev" and compiler.get("go_version") == "go1.27.2" and
            compiler.get("vcs_modified") == "false", "generation producer identity differs")
    require(set(record["activities"]) == {"CompletionStep", "CompletionFinish", "CompletionReady"}, "generation activity roster differs")
    for activity, generated_record in record["activities"].items():
        receipt = generated_record["report"]
        activity_id = "gooo://automation/completion-ready" if activity == "CompletionReady" else "gooo://rea/completion-" + activity[10:].lower()
        require(receipt["schema"] == "gooo/body-codegen-report/v3" and receipt["decision"] == "PASS" and
                receipt["activity"] == activity and receipt["activity_id"] == activity_id and
                receipt["compiler_source_sha"] == PIN and receipt["source_digest"] == expected["source_sha256"] and
                receipt["generated_digest"] == sha(generated_record["source"].encode()) and
                receipt["typecheck_passed"] is True and receipt["deterministic_replay"] is True and
                type(receipt["repository_writes"]) is int and receipt["repository_writes"] == 0,
                "generation activity byte/producer/typecheck binding differs")
    return expected


def cli(binary, policy_path, payload, env, replay=False, use_file=False, scratch=None):
    argv = [str(binary), "--policy", str(policy_path)]
    if replay:
        argv.append("--replay")
    if use_file:
        scratch.write_bytes(payload)
        argv.extend(["--input", str(scratch)])
    result = subprocess.run(argv, input=None if use_file else payload, env=env, cwd=PROJECT,
                            capture_output=True, timeout=15)
    return result


def rejected_cli(binary, policy_path, payload, env, name, replay=False):
    result = cli(binary, policy_path, payload, env, replay)
    require(result.returncode == 2 and result.stdout == b"" and len(result.stderr) > 0,
            "malformed CLI case was not rejected with exit2 and no report: " + name)
    return {"name": name, "exit_code": result.returncode, "payload_sha256": sha(payload), "diagnostic_sha256": sha(result.stderr)}


def malformed_cli(binary, host, bindings, env, out, saved):
    policy_path, raw_policy = out / "invalid-policy.json", encode(host[0]["policy"])
    policy_path.write_bytes(raw_policy)
    base, invalid = host[0]["input"], {}
    def changed(name, mutate):
        candidate = copy.deepcopy(base)
        mutate(candidate)
        invalid[name] = encode(candidate)
    changed("unknown_input_field", lambda d: d.update(required_claims=["claim_000"]))
    changed("case_alias_input_field", lambda d: d.update(Schema=d["schema"]))
    changed("missing_records", lambda d: d.pop("records"))
    changed("null_records", lambda d: d.update(records=None))
    changed("duplicate_claim_id", lambda d: d["records"].append(copy.deepcopy(d["records"][0])))
    changed("duplicate_evidence_id", lambda d: d["records"][0]["evidence_ids"].append(d["records"][0]["evidence_ids"][0]))
    changed("unknown_status", lambda d: d["records"][0].update(status="PASS"))
    changed("status_boolean", lambda d: d["records"][0].update(status=True))
    changed("unknown_record_field", lambda d: d["records"][0].update(complete=True))
    changed("missing_evidence_ids", lambda d: d["records"][0].pop("evidence_ids"))
    changed("empty_evidence_ids", lambda d: d["records"][0].update(evidence_ids=[]))
    changed("invalid_evidence_hex", lambda d: d["records"][0].update(evidence_ids=["ev_" + "A" * 64]))
    changed("identifier_81_characters", lambda d: d.update(request_id="a" * 81))
    changed("identifier_non_ascii", lambda d: d.update(request_id="요청"))
    changed("257_records", lambda d: d.update(records=[{**d["records"][0], "claim_id": f"claim_{i}"} for i in range(257)]))
    changed("257_evidence_ids", lambda d: d["records"][0].update(evidence_ids=["ev_" + f"{i:064x}" for i in range(257)]))
    invalid.update({"duplicate_json_key": b'{"schema":"policy-studio/completion-input/v1","schema":"policy-studio/completion-input/v1","request_id":"r","records":[]}',
                    "invalid_utf8": b'{"schema":"policy-studio/completion-input/v1","request_id":"\xff","records":[]}',
                    "unpaired_utf16": b'{"schema":"policy-studio/completion-input/v1","request_id":"\\ud800","records":[]}',
                    "input_over_byte_limit": b" " * 1048577, "empty_input": b"", "trailing_json": encode(base) + b"{}"})
    rejected = [rejected_cli(binary, policy_path, payload, env, name) for name, payload in invalid.items()]
    for name, mutate in {
        "policy_zero_revision": lambda d: d.update(revision=0),
        "policy_negative_revision": lambda d: d.update(revision=-1),
        "policy_revision_float": lambda d: d.update(revision=1.0),
        "policy_revision_boolean": lambda d: d.update(revision=True),
        "policy_revision_overflow": lambda d: d.update(revision=1 << 63),
        "policy_empty_claims": lambda d: d.update(required_claims=[]),
        "policy_duplicate_claim": lambda d: d["required_claims"].append(d["required_claims"][0]),
        "policy_257_claims": lambda d: d.update(required_claims=[f"claim_{i}" for i in range(257)]),
        "policy_extra_field": lambda d: d.update(input=base),
        "policy_case_alias": lambda d: d.update(Policy_id=d["policy_id"]),
        "policy_null_claims": lambda d: d.update(required_claims=None),
    }.items():
        candidate = copy.deepcopy(host[0]["policy"])
        mutate(candidate)
        payload = encode(candidate)
        policy_path.write_bytes(payload)
        row = rejected_cli(binary, policy_path, encode(base), env, name)
        row["policy_sha256"] = sha(payload)
        rejected.append(row)
    for name, payload in (("policy_over_byte_limit", b" " * 65537), ("empty_policy", b"")):
        policy_path.write_bytes(payload)
        row = rejected_cli(binary, policy_path, encode(base), env, name)
        row["policy_sha256"] = sha(payload)
        rejected.append(row)
    policy_path.write_bytes(raw_policy)
    mutations = {
        "replay_summary_count": lambda d: d["summary"].update(total=2),
        "replay_summary_valid": lambda d: d["summary"].update(valid=False),
        "replay_readiness_boolean": lambda d: d["readiness"].update(ready=False),
        "replay_readiness_integer_alias": lambda d: d["readiness"].update(ready=1),
        "replay_step_index": lambda d: d["steps"][0].update(index=1),
        "replay_step_counts_before": lambda d: d["steps"][0]["counts_before"].update(total=1),
        "replay_step_status": lambda d: d["steps"][0].update(status="fail"),
        "replay_step_decision": lambda d: d["steps"][0]["decision"].update(reason="DIFFERENT"),
        "replay_missing_step": lambda d: d["steps"].pop(),
        "replay_coverage": lambda d: d["coverage"].update(observed_count=2),
        "replay_missing_claims": lambda d: d.update(missing_claims=["claim_000"]),
        "replay_unexpected_claims": lambda d: d.update(unexpected_claims=["claim_000"]),
        "replay_embedded_policy": lambda d: d["policy"].update(revision=2),
        "replay_input_status": lambda d: d["input"]["records"][0].update(status="fail"),
        "replay_schema": lambda d: d.update(schema="policy-studio/completion-report/v2"),
        "replay_extra_field": lambda d: d.update(approved=True),
    }
    for field in ["policy_sha256"] + list(bindings):
        mutations["replay_binding_" + field] = lambda d, f=field: d["bindings"].update({f: "0" * 40 if f == "compiler_source_sha" else "sha256:" + "0" * 64})
    for name, mutate in mutations.items():
        candidate = copy.deepcopy(saved)
        mutate(candidate)
        require(not exact(candidate, saved), "replay mutation was a no-op: " + name)
        rejected.append(rejected_cli(binary, policy_path, encode(candidate), env, name, True))
    current_policy = copy.deepcopy(host[0]["policy"])
    current_policy["revision"] = 2
    for name, raw in (("replay_current_policy_revision", encode(current_policy)),
                      ("replay_current_policy_same_semantics_different_bytes", raw_policy + b" ")):
        policy_path.write_bytes(raw)
        row = rejected_cli(binary, policy_path, encode(saved), env, name, True)
        row["policy_sha256"] = sha(raw)
        rejected.append(row)
    policy_path.write_bytes(raw_policy)
    rejected.append(rejected_cli(binary, policy_path, b" " * 4194305, env, "replay_over_byte_limit", True))
    return rejected


def observe_host(books, go, out, env):
    host_out = out / "host"
    host_out.mkdir()
    binary = out / ("completion-check.exe" if os.name == "nt" else "completion-check")
    command([go, "build", "-trimpath", "-o", str(binary), "./cmd/completion-check"], env)
    bindings = source_bindings()
    policy_path, scratch = host_out / "policy.json", host_out / "input.json"
    records, first_report = [], None
    for index, case in enumerate(books["host-cases.json"]):
        raw_policy, raw_input = encode(case["policy"]), encode(case["input"])
        policy_path.write_bytes(raw_policy)
        result = cli(binary, policy_path, raw_input, env, use_file=index % 2 == 0, scratch=scratch)
        expected_code = case["expected"]["exit_code"]
        require(result.returncode == expected_code and result.stderr == b"", "actual host exit code/diagnostics differ at fixture " + str(index))
        actual = strict_json(result.stdout)
        expected = {**case["expected"]["report"], "bindings": {**bindings, "policy_sha256": sha(raw_policy)}}
        require(exact(actual, expected), "complete host report differs from independent literal/bindings at fixture " + str(index))
        report_path = host_out / f"host-{index:04d}-report.json"
        report_path.write_bytes(result.stdout)
        replay = cli(binary, policy_path, result.stdout, env, True, use_file=index % 2 != 0, scratch=scratch)
        require(replay.returncode == expected_code and replay.stderr == b"" and exact(strict_json(replay.stdout), expected),
                "whole host CLI replay or actual exit differs at fixture " + str(index))
        (host_out / f"host-{index:04d}-replay.json").write_bytes(replay.stdout)
        records.append({"index": index, "records": len(case["input"]["records"]), "exit_code": result.returncode,
                        "replay_exit_code": replay.returncode, "whole_report_equal": True, "whole_replay_equal": True,
                        "policy_sha256": sha(raw_policy), "input_sha256": sha(raw_input),
                        "report_sha256": sha(result.stdout), "replay_sha256": sha(replay.stdout)})
        if index == 0:
            first_report = actual
        if (index + 1) % 100 == 0 or index + 1 == len(books["host-cases.json"]):
            print(json.dumps({"host_observed": index + 1, "whole_report_and_replay_equal": True}), flush=True)
    rejected = malformed_cli(binary, books["host-cases.json"], bindings, env, host_out, first_report)
    return {"cases": len(records), "passed": len(records), "whole_report_and_replay_equal": True,
            "actual_exit_codes_observed": sorted({r["exit_code"] for r in records} | {r["exit_code"] for r in rejected}),
            "binary_sha256": sha(binary.read_bytes()), "bindings": bindings,
            "original_cases_sha256": sha((EXAMPLE / "cases/host-cases.json").read_bytes()),
            "records": records, "rejected_cli_cases": rejected,
            "scope": "Built command, alternating file/stdin input and replay. Every independent semantic field and ordered step plus current actual byte bindings checked. Replay proves internal consistency, not authenticity of supplied identifiers or outcomes."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--go", help="Go1.27.2 executable; defaults to the executable on PATH")
    parser.add_argument("--host-go", help="Go1.27.3 executable for the current Policy Studio host CLI")
    parser.add_argument("--output", "--out", dest="output", required=True)
    args = parser.parse_args()
    out = Path(args.output).resolve()
    require(not out.exists(), "use a fresh completion output directory")
    compiler = str(Path(args.compiler).resolve())
    go = str(Path(args.go or shutil.which("go") or "").resolve())
    host_go = str(Path(args.host_go or shutil.which("go") or "").resolve())
    require(Path(compiler).is_file() and Path(go).is_file() and Path(host_go).is_file(),
            "select existing compiler and Go executables")
    books, integrity = fixture_integrity()
    source_bindings()
    env = dict(os.environ)
    for key in ("GOOO_LAYA_URL", "GOOO_LAYA_API_KEY"):
        env.pop(key, None)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"})
    require((EXAMPLE / "compiler-version.txt").read_text().strip() == PIN, "compiler declaration differs")
    identity = strict_json(command([compiler, "version", "--build", "--json"], env, 15))
    require(identity["compiler_source_sha"] == PIN and identity["version"] == "0.6.32-dev" and
            identity["source_status"] == "CLEAN_VCS" and identity["vcs_modified"] == "false" and
            identity["go_version"] == "go1.27.2", "compiler identity differs")
    go_digest = sha(Path(go).read_bytes())
    go_version = command([go, "version"], env, 15).decode().strip()
    require(go_version.startswith("go version go1.27.2 "), "selected Go version differs")
    host_go_version = command([host_go, "version"], env, 15).decode().strip()
    require(host_go_version.startswith("go version go1.27.3 "), "selected host Go version differs")
    out.mkdir(parents=True)
    report = {"schema": "policy-studio/completion-ledger-observation/v1", "compiler": identity,
              "go_version": go_version, "go_tool_sha256": go_digest,
              "host_go_version": host_go_version, "host_go_tool_sha256": sha(Path(host_go).read_bytes()),
              "fixture_integrity": integrity}
    report["original_reference"] = original_reference(books, env, out)
    report["runs"] = observe_native(books, compiler, go, out, env, go_digest)
    report["host"] = observe_host(books, host_go, out, env)
    report["source_files"] = {str(p.relative_to(PROJECT)): sha(p.read_bytes()) for p in sorted(EXAMPLE.rglob("*")) if p.is_file()}
    report["helper_files"] = {str(Path(__file__).relative_to(PROJECT)): sha(Path(__file__).read_bytes()),
                              "tools/verify-evidence-admission.py": sha((PROJECT / "tools/verify-evidence-admission.py").read_bytes())}
    report["scope"] = "5293 independent finite Gooo core cases and803 variable-length CLI examples, including256 records; complete native receipts, ordered inputs/full outputs and whole replay checked. Supplied unsigned verifier outcomes and operator-selected policy. No evidence authentication, permission grant, target effect, remote exactly-once, model call, full REA RFC8785 ledger compatibility, customer adoption or all-input safety claim. Inner typed-plan/runtime-suite digests are not independently recomputed."
    (out / "observations.json").write_bytes(json.dumps(report, indent=2).encode() + b"\n")
    print(json.dumps({"passed": True, "core_cases": sum(r["cases"] for r in report["runs"]),
                      "native_batches": sum(len(r["batches"]) for r in report["runs"]),
                      "host_cases": report["host"]["cases"], "rejected_cli_cases": len(report["host"]["rejected_cli_cases"])}))


if __name__ == "__main__":
    main()
