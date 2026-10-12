#!/usr/bin/env python3
"""Observe separately pinned Gooo evidence policies and replay complete receipts.

This runs only the supplied compiler, its Go projection and one isolated pure
REA function. It never executes a target application or performs an admitted effect.
"""
import argparse
import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT / "examples/evidence-admission"
ENTRY_AUTHORITY = "rea/proof-authority:ProofAuthoritySatisfies"
ENTRY_ADMISSION = "app/evidence-admission:EvidenceAdmission"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(exact(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError("nonfinite JSON constant: " + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read(path):
    return strict_json(path.read_bytes())


def source_image_digest(path):
    # package-runtime source images hash Go's JSON encoding of a string, not
    # its raw bytes. Raw file hashes are recorded separately in this report.
    encoded = json.dumps(path.read_text(), ensure_ascii=False, separators=(",", ":"))
    for plain, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                           ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        encoded = encoded.replace(plain, escaped)
    return sha(encoded.encode())


def command(argv, env, timeout=180):
    result = subprocess.run(argv, cwd=PROJECT, env=env, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        try:
            detail = strict_json(result.stdout).get("error", "no compiler error field")
        except (ValueError, UnicodeError, AttributeError):
            detail = result.stderr.decode(errors="replace")[:1000]
        raise ValueError("command failed: " + Path(argv[0]).name + ": " + str(detail)[:2000])
    return result.stdout


def original_authority_reference(env):
    upstream = read(EXAMPLE / "upstream.json")
    source = (EXAMPLE / "upstream/ReconstructionObligationAuthority.ts").read_bytes()
    require(sha(source) == "sha256:" + upstream["source_sha256"], "REA source bytes differ")
    require(sha((EXAMPLE / "LICENSE-REA").read_bytes()) == "sha256:" + upstream["license_sha256"], "REA notice differs")
    text = source.decode()
    block = text[text.index("export const proofAuthoritySatisfies ="):text.index("/** Check that Evidence can authenticate")].strip()
    require(block.count(": ProofAuthority") == 2 and block.count("): boolean =>") == 1 and
            block.count("const accepted: Readonly<Record<ProofAuthority, readonly ProofAuthority[]>> =") == 1,
            "review the isolated TypeScript extraction after a source change")
    js = block.replace("export const", "const", 1).replace(": ProofAuthority", "").replace("): boolean =>", ") =>").replace(
        "const accepted: Readonly<Record<ProofAuthority, readonly ProofAuthority[]>> =", "const accepted =")
    labels = ["unit", "integration", "protocol", "renderer", "packaged-process", "native-abi", "live-observation", "external"]
    js += "\nconst labels=" + json.dumps(labels) + "; process.stdout.write(JSON.stringify(labels.flatMap(required=>labels.map(actual=>({actual,required,result:proofAuthoritySatisfies(actual,required)})))));\n"
    result = subprocess.run(["node"], input=js.encode(), env=env, capture_output=True, timeout=10)
    require(result.returncode == 0, "isolated REA pure function failed")
    rows = strict_json(result.stdout)
    cases = read(EXAMPLE / "cases-73.json")["cases"]
    require(len(rows) == 64 and len(cases) == 73 and sum(row["result"] for row in rows) == 25, "authority domain differs")
    for row, case in zip(rows, cases[:64]):
        require(exact(case["inputs"], {ENTRY_AUTHORITY + ".input0": row["actual"], ENTRY_AUTHORITY + ".input1": row["required"]}) and
                exact(case["expected"], {ENTRY_AUTHORITY: row["result"]}), "original authority fixture differs")
    require(all(case["expected"][ENTRY_AUTHORITY] is False for case in cases[64:]), "invalid-label extension must reject")
    return {"source_sha256": sha(source), "isolated_function_sha256": sha(js.encode()), "pairs": 64, "matched": 64,
            "true": 25, "false": 39, "extension_cases": 9, "scope": "One isolated pure function; only TypeScript annotations/export removed. No REA setup or application execution."}


def validate(receipt, workspace, cases_file, entry, pin, go_digest):
    cases = read(cases_file)["cases"]
    require(receipt["schema"] == "gooo/workspace-body-execution-receipt/v1" and receipt["decision"] == "PASS", "execution decision differs")
    require(receipt["manifest_digest"] == sha(workspace.read_bytes()) and receipt["cases_digest"] == sha(cases_file.read_bytes()), "input byte binding differs")
    result = receipt["result"]
    composition, runtime, program = result["composition"], result["runtime"], result["program"]
    require(composition["stage"] == runtime["stage"] == "COMPLETE", "projection did not complete")
    lowered = sha(program["lowered_gooo_source"].encode())
    require(result["execution_source_sha256"] == composition["original_source_sha256"] == composition["selected_source_sha256"] ==
            runtime["original_source_sha256"] == runtime["selected_source_sha256"] == lowered, "lowered source binding differs")
    require(composition["generated_sha256"] == runtime["generated_sha256"] == sha(composition["source"].encode()) and
            composition["driver_sha256"] == runtime["driver_sha256"] == sha(composition["driver_source"].encode()), "generated byte binding differs")
    image_packages = program["workspace_image"]["packages"]
    packages = {p["path"]: p for p in image_packages}
    require(len(packages) == len(image_packages), "duplicate package path")
    require(set(packages) == {p["path"] for p in read(workspace)["packages"]}, "package roster differs")
    for selector in (program["entry"], program["workspace_image"]["entry"]):
        require({k: selector[k] for k in ("package_path", "activity")} == read(workspace)["entry"], "entry selector differs")
    for package in read(workspace)["packages"]:
        source_images = packages[package["path"]]["sources"]
        actual = {s["filename"]: s["source_digest"] for s in source_images}
        expected = {name: source_image_digest(EXAMPLE / name) for name in package["sources"]}
        require(len(actual) == len(source_images) and actual == expected, "package source image differs")
    require(runtime["producer_source_sha"] == pin and runtime["go_tool_sha256"] == go_digest and
            runtime["go_version"].startswith("go version go1.27.2 ") and type(runtime["model_calls"]) is int and runtime["model_calls"] == 0, "producer or model scope differs")
    for execution in [runtime["toolchain"], runtime["build"]] + runtime["runs"]:
        require(execution["started"] is True and execution["completed"] is True and type(execution["exit_code"]) is int and execution["exit_code"] == 0 and
                execution["canceled"] is False and execution["timed_out"] is False and execution["output_truncated"] is False, "native command did not finish successfully")
    require(len(runtime["runs"]) == 2 and runtime["projection_replayed"] is True and runtime["runtime_replayed"] is True and
            type(runtime["finite_total"]) is int and type(runtime["finite_passed"]) is int and runtime["finite_total"] == len(cases) and runtime["finite_passed"] == len(cases), "finite runtime scope differs")
    traces = runtime["traces"]
    require(len(traces) == len(cases), "trace roster differs")
    activity = next(e for p in packages.values() for e in p["exports"] if p["path"] + ":" + e["name"] == entry)
    for index, (trace, case) in enumerate(zip(traces, cases)):
        require(type(trace["case_index"]) is int and trace["case_index"] == index and len(trace["deliveries"]) == 1, "ordered case trace differs")
        delivery = trace["deliveries"][0]
        if entry in case["inputs"]:
            expected_inputs, actual_inputs = [case["inputs"][entry]], [delivery["input"]]
        else:
            expected_inputs = [case["inputs"][entry + ".input0"], case["inputs"][entry + ".input1"]]
            actual_inputs = [v["value"] for v in delivery["inputs"]]
        require(delivery["activity_id"] == activity["id"] and exact(actual_inputs, expected_inputs) and
                exact(delivery["actual"], case["expected"][entry]) and exact(delivery["expected"], case["expected"][entry]) and delivery["passed"] is True,
                "actual ordered input or complete expected result differs")
    return runtime


def mutation_checks(receipt, workspace, cases_file, entry, pin, go_digest):
    def change_input(document):
        delivery = document["result"]["runtime"]["traces"][-1]["deliveries"][0]
        if entry == ENTRY_ADMISSION:
            delivery["input"] = "different"
        else:
            delivery["inputs"][0]["value"] = "different"
    mutations = {
        "boolean_integer_alias": lambda d: d["result"]["runtime"]["traces"][-1]["deliveries"][0].update(passed=1),
        "late_actual_result_changed": lambda d: d["result"]["runtime"]["traces"][-1]["deliveries"][0].update(actual=None),
        "late_input_changed": change_input,
        "duplicate_case_index": lambda d: d["result"]["runtime"]["traces"][-1].update(case_index=0),
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
        try:
            validate(candidate, workspace, cases_file, entry, pin, go_digest)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("receipt mutation accepted: " + name)
    return list(mutations)


def batches(cases_file, out, name):
    """Retain every ordered fixture under the compiler's 32KiB JSON bound."""
    document = read(cases_file)
    if cases_file.stat().st_size <= 30000:
        return [cases_file]
    groups, current = [], []
    def encode(rows):
        return json.dumps({"schema": document["schema"], "cases": rows}, ensure_ascii=False, separators=(",", ":")).encode()
    for case in document["cases"]:
        require(len(encode([case])) <= 30000, "one fixture exceeds the bounded JSON profile")
        if current and len(encode(current + [case])) > 30000:
            groups.append(current)
            current = []
        current.append(case)
    if current:
        groups.append(current)
    require(exact([case for group in groups for case in group], document["cases"]), "batching changed ordered fixtures")
    paths = []
    for index, group in enumerate(groups):
        path = out / f"{name}-{index:03d}-cases.json"
        path.write_bytes(encode(group))
        paths.append(path)
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--authority-receipts", help="Reuse execution-73.json/replay-73.json for the unchanged pure relation only, after every source/input/runtime binding is checked; CI omits this option")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    require(not out.exists(), "use a fresh evidence output directory")
    out.mkdir(parents=True)
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"})
    pin = (EXAMPLE / "compiler-version.txt").read_text().strip()
    identity = strict_json(command([args.compiler, "version", "--build", "--json"], env, 15))
    require(identity["compiler_source_sha"] == pin and identity["version"] == "0.6.32-dev" and identity["source_status"] == "CLEAN_VCS" and
            identity["vcs_modified"] == "false" and identity["go_version"] == "go1.27.2", "compiler identity differs")
    go_digest = sha(Path(args.go).read_bytes())
    reference = original_authority_reference(env)
    report = {"schema": "policy-studio/evidence-admission-observation/v1", "compiler": identity, "original_reference": reference, "runs": []}
    for name, workspace_name, cases_name, entry in (("authority", "authority.workspace.json", "cases-73.json", ENTRY_AUTHORITY),
                                                   ("admission", "gooo.workspace.json", "cases/admission-cases.json", ENTRY_ADMISSION)):
        workspace, original_cases = EXAMPLE / workspace_name, EXAMPLE / cases_name
        total, offset = len(read(original_cases)["cases"]), 0
        records = []
        for index, cases in enumerate(batches(original_cases, out, name)):
            label = name + f"-{index:03d}"
            receipt_path = out / (label + "-execution.json")
            reused = name == "authority" and args.authority_receipts is not None
            raw = (Path(args.authority_receipts) / "execution-73.json").read_bytes() if reused else command(
                [args.compiler, "package", "execute", "--json", "--go", args.go, "--cases", str(cases), str(workspace)], env)
            receipt_path.write_bytes(raw)
            receipt = strict_json(raw)
            runtime = validate(receipt, workspace, cases, entry, pin, go_digest)
            replay_raw = (Path(args.authority_receipts) / "replay-73.json").read_bytes() if reused else command(
                [args.compiler, "package", "replay", "--json", "--go", args.go, "--receipt", str(receipt_path), "--cases", str(cases), str(workspace)], env)
            (out / (label + "-replay.json")).write_bytes(replay_raw)
            replay = strict_json(replay_raw)
            second = validate(replay, workspace, cases, entry, pin, go_digest)
            require(replay["replayed_from_sha256"] == sha(raw) and exact(runtime["traces"], second["traces"]) and
                    receipt["result"]["composition"]["source"] == replay["result"]["composition"]["source"] and
                    receipt["result"]["composition"]["driver_source"] == replay["result"]["composition"]["driver_source"] and
                    receipt["result"]["program"]["lowered_gooo_source"] == replay["result"]["program"]["lowered_gooo_source"], "whole receipt replay differs")
            rejected = mutation_checks(receipt, workspace, cases, entry, pin, go_digest)
            records.append({"offset": offset, "cases": runtime["finite_total"], "passed": runtime["finite_passed"], "whole_replay_equal": True,
                            "native_execution_this_invocation": not reused, "cases_sha256": sha(cases.read_bytes()),
                            "execution_sha256": sha(raw), "replay_sha256": sha(replay_raw), "rejected_receipt_mutations": rejected})
            offset += runtime["finite_total"]
        require(offset == total, "not every original fixture was observed")
        report["runs"].append({"name": name, "cases": total, "passed": offset, "whole_replay_equal": True,
                               "original_cases_sha256": sha(original_cases.read_bytes()), "batches": records})
    report["source_files"] = {str(p.relative_to(PROJECT)): sha(p.read_bytes()) for p in sorted(EXAMPLE.rglob("*")) if p.is_file()}
    report["scope"] = "Finite synthetic trusted-fact projection and original authority relation. No evidence authentication, real capability grant, host effect, target application, model call, or all-input safety proof. Unsigned byte consistency; inner typed-plan/runtime-suite digests not independently recomputed."
    (out / "observations.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "runs": report["runs"], "scope": report["scope"]}))


if __name__ == "__main__":
    main()
