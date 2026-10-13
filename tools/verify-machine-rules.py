#!/usr/bin/env python3
"""Verify only the new final machine relation through native execution/replay.

The generation closure check is a separate invocation of cmd/generate-machine.
This tool does not rerun the old evidence/effect/completion native suites.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

PROJECT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT / "examples/artifact-gate"
ENTRY = "gooo/artifact-gate:ArtifactGateAdmits"
SPEC = importlib.util.spec_from_file_location("machine_receipt_checks", PROJECT / "tools/verify-evidence-admission.py")
RECEIPTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPTS)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(args, env):
    run = subprocess.run(args, cwd=PROJECT, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=90, check=False)
    require(run.returncode == 0, "native command failed: " + run.stderr.decode("utf-8", "replace"))
    return run.stdout


def typed_fields(receipt, cases):
    steps = receipt["result"]["composition"]["steps"]
    require(len(steps) == 1, "new relation must have one generated entry step")
    records = steps[0]["generation"]["report"]["record_types"]
    by_name = {record["name"]: record for record in records}
    require(len(by_name) == len(records) and set(by_name) == {"AdmissionFacts", "AdmissionDecision"},
            "declared record roster differs")
    scalar = {"urn:gooo:type:boolean": bool, "urn:gooo:type:integer": int, "urn:gooo:type:string": str}
    for trace, case in zip(receipt["result"]["runtime"]["traces"], cases):
        delivery = trace["deliveries"][0]
        for record_name, field_key, values in (
            ("AdmissionFacts", "input_fields", case["inputs"][ENTRY]),
            ("AdmissionDecision", "actual_fields", case["expected"][ENTRY]),
        ):
            metadata = by_name[record_name]["fields"]
            require(len(metadata) == len(values), "typed source field roster differs")
            wanted = []
            for field in metadata:
                require(field["name"] in values and field["type_id"] in scalar,
                        "unknown typed source field")
                value = values[field["name"]]
                require(type(value) is scalar[field["type_id"]], "literal field type differs")
                wanted.append({"id": field["id"], "name": field["name"], "value": value})
            require(RECEIPTS.exact(delivery[field_key], wanted), "ordered typed input/output fields differ")


def validate(receipt, workspace, cases_file, pin, go_sha):
    runtime = RECEIPTS.validate(receipt, workspace, cases_file, ENTRY, pin, go_sha, EXAMPLE)
    typed_fields(receipt, RECEIPTS.read(cases_file)["cases"])
    return runtime


def typed_mutations(receipt, workspace, cases_file, pin, go_sha):
    def field(document, key):
        return document["result"]["runtime"]["traces"][-1]["deliveries"][0][key]

    mutations = {
        "changed_input_field_id": lambda d: field(d, "input_fields")[0].update(id="changed"),
        "changed_input_field_value": lambda d: field(d, "input_fields")[0].update(value="true"),
        "changed_output_field_id": lambda d: field(d, "actual_fields")[0].update(id="changed"),
        "changed_output_field_value": lambda d: field(d, "actual_fields")[0].update(value="false"),
        "duplicate_typed_output_field": lambda d: field(d, "actual_fields").append(copy.deepcopy(field(d, "actual_fields")[0])),
    }
    rejected = []
    for name, mutation in mutations.items():
        changed = copy.deepcopy(receipt)
        mutation(changed)
        require(not RECEIPTS.exact(changed, receipt), "verifier mutation was a no-op")
        try:
            validate(changed, workspace, cases_file, pin, go_sha)
        except (ValueError, KeyError, TypeError, AssertionError):
            rejected.append(name)
        else:
            raise ValueError("changed typed receipt accepted: " + name)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--reuse", help="Reuse only this new relation's existing native execute/replay receipts after every current binding is checked; CI omits this option")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.pop("GOOO_LAYA_URL", None)
    env.pop("GOOO_LAYA_API_KEY", None)
    pin = (EXAMPLE / "compiler-version.txt").read_text().strip()
    identity_raw = command([args.compiler, "version", "--build", "--json"], env)
    identity = RECEIPTS.strict_json(identity_raw)
    require(pin == "83928fa4538245abe33b08549da47f8cbdc50ed2" and
            identity["compiler_source_sha"] == identity["vcs_revision"] == pin and
            identity["version"] == "0.6.32-dev" and identity["source_status"] == "CLEAN_VCS" and
            identity["vcs_modified"] == "false" and identity["go_version"] == "go1.27.2" and
            identity["native_go_required"] == "go1.27.2", "actual pinned compiler identity differs")
    (out / "compiler-identity.json").write_bytes(identity_raw)
    go_sha = sha(Path(args.go).read_bytes())
    workspace = EXAMPLE / "admission.workspace.json"
    cases_file = EXAMPLE / "admission-cases.json"
    cases = RECEIPTS.read(cases_file)["cases"]
    require(len(cases) == 31, "declared new final corpus differs")
    # Inspect the advertised complete four-condition table, rather than using
    # its row count as indirect evidence that all combinations are present.
    combinations = set()
    for case in cases[:16]:
        facts = case["inputs"][ENTRY]
        require(facts["required_count"] == facts["observed_count"] == 1 and
                facts["provenance_ok"] is True and facts["control_plane_effect_admissible"] is True and
                type(facts["admissible_evidence_count"]) is int and facts["admissible_evidence_count"] in (0, 1),
                "declared four-condition table context differs")
        combinations.add((facts["base_policy_approved"], facts["admissible_evidence_count"] == 1,
                          facts["completion_ready"], facts["approval_effect_admissible"]))
    require(len(combinations) == 16, "four-condition table omits a combination")
    raw = (Path(args.reuse) / "admission-execution.json").read_bytes() if args.reuse else command(
        [args.compiler, "package", "execute", "--json", "--go", args.go,
         "--cases", str(cases_file), str(workspace)], env)
    execution_file = out / "admission-execution.json"
    execution_file.write_bytes(raw)
    first = RECEIPTS.strict_json(raw)
    runtime = validate(first, workspace, cases_file, pin, go_sha)
    replay_raw = (Path(args.reuse) / "admission-replay.json").read_bytes() if args.reuse else command(
        [args.compiler, "package", "replay", "--json", "--go", args.go,
         "--receipt", str(execution_file), "--cases", str(cases_file), str(workspace)], env)
    (out / "admission-replay.json").write_bytes(replay_raw)
    second = RECEIPTS.strict_json(replay_raw)
    replay_runtime = validate(second, workspace, cases_file, pin, go_sha)
    require(second["replayed_from_sha256"] == sha(raw) and
            RECEIPTS.exact(runtime["traces"], replay_runtime["traces"]) and
            first["result"]["composition"]["source"] == second["result"]["composition"]["source"] and
            first["result"]["composition"]["driver_source"] == second["result"]["composition"]["driver_source"] and
            first["result"]["program"]["lowered_gooo_source"] == second["result"]["program"]["lowered_gooo_source"],
            "whole new final native replay differs")
    rejected = RECEIPTS.mutation_checks(first, workspace, cases_file, ENTRY, pin, go_sha, EXAMPLE)
    rejected += typed_mutations(first, workspace, cases_file, pin, go_sha)
    report = {
        "schema": "policy-studio/machine-rules-observation/v1",
        "status": "NEW_FINAL_NATIVE_AND_WHOLE_REPLAY_ACCEPTED",
        "compiler": identity,
        "measured_native_go_sha256": go_sha,
        "entry": ENTRY,
        "cases": runtime["finite_total"],
        "passed": runtime["finite_passed"],
        "four_condition_combinations": len(combinations),
        "additional_boundaries": 15,
        "whole_replay_equal": True,
        "ordered_typed_field_values_checked": True,
        "native_execution_this_invocation": args.reuse is None,
        "execution_sha256": sha(raw),
        "replay_sha256": sha(replay_raw),
        "rejected_receipt_mutations": rejected,
        "source_files": {str(p.relative_to(PROJECT)): sha(p.read_bytes())
                         for p in sorted(EXAMPLE.rglob("*")) if p.is_file()},
        "generation_record_sha256": sha((PROJECT / "internal/machinerules/generation.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "shared_receipt_verifier_sha256": sha((PROJECT / "tools/verify-evidence-admission.py").read_bytes()),
        "scope": "New final relation only. Retained evidence/effect native closure observations are checked separately by generate-machine --check. No old native suites repeated; no artifact authentication, external execution, production or universal safety claim.",
    }
    (out / "observations.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"entry": ENTRY, "cases": report["cases"], "passed": report["passed"],
                      "whole_replay_equal": True, "rejected_mutations": len(rejected)}))


if __name__ == "__main__":
    main()
