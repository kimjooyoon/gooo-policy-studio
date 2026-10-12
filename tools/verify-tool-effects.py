#!/usr/bin/env python3
"""Observe two pinned REA pure functions and an original Gooo effect budget.

Runs the supplied compiler and its Go projection; never invokes a target tool.
Expected cases were authored separately from the Gooo candidate and this runner.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
EXAMPLE = PROJECT / "examples/tool-effects"
spec = importlib.util.spec_from_file_location("evidence_receipts", PROJECT / "tools/verify-evidence-admission.py")
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)
require, sha, exact, read = receipts.require, receipts.sha, receipts.exact, receipts.read
strict_json, command, batches = receipts.strict_json, receipts.command, receipts.batches
PREFIX = "gooo/tool-effects:"
ENTRY_ANNOTATIONS = PREFIX + "AnnotationsFromEffects"
ENTRY_CONTENT = PREFIX + "ToolReturnsTargetContent"
ENTRY_BUDGET = PREFIX + "EffectBudgetAccepts"
FIELDS = ["mutatesTarget", "mutatesSession", "writesFilesystem", "launchesProcess", "accessesNetwork",
          "changesUiState", "mayDiscardData", "executesForeignCode", "mutatesDevice", "idempotent"]
SOURCE_SHA = "c6437904a505f1fee0d0547f05ddef629bda74168420b8f6424a5413ab1f1dfb"
LICENSE_SHA = "798f9e4d18e49b30bf2f12696c8ced73dc4e1413da375a333d01281543a1ea8b"
PIN = "83928fa4538245abe33b08549da47f8cbdc50ed2"


def original_reference(env):
    metadata = read(EXAMPLE / "upstream.json")
    source = (EXAMPLE / "upstream/toolEffects.ts").read_bytes()
    license_bytes = (EXAMPLE / "LICENSE-REA").read_bytes()
    require(metadata["commit"] == "8fc2043eb8bcedbf34dce064f977e455438635d6" and
            metadata["source_sha256"] == SOURCE_SHA and sha(source) == "sha256:" + SOURCE_SHA and
            metadata["license_sha256"] == LICENSE_SHA and sha(license_bytes) == "sha256:" + LICENSE_SHA,
            "pinned upstream source or license differs")
    for name, raw in (("source", source), ("license", license_bytes)):
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        require(metadata[name + "_bytes"] == len(raw) and metadata[name + "_git_blob_sha1"] == blob,
                "upstream Git blob or size differs")
    text = source.decode("utf-8")
    start = text.index("export const annotationsFromEffects =")
    annotation = text[start:text.index("});", start) + 3]
    replacements = (("export const", "const"), ("value: ToolEffects,", "value,"),
                    ("): DerivedToolAnnotations =>", ") =>"))
    for before, after in replacements:
        require(annotation.count(before) == 1, "review changed annotation extraction")
        annotation = annotation.replace(before, after, 1)
    start = text.index("export const TARGET_CONTENT_FREE_TOOLS:")
    content = text[start:text.index("/** Resolve the audited metadata", start)]
    require(content.count("export const") == 2 and content.count(": ReadonlySet<string>") == 1 and
            content.count("(name: string): boolean =>") == 1, "review changed content extraction")
    content = content.replace("export const", "const").replace(": ReadonlySet<string>", "").replace("(name: string): boolean =>", "(name) =>")
    annotation_cases = read(EXAMPLE / "cases/annotations-cases.json")["cases"]
    content_cases = read(EXAMPLE / "cases/content-cases.json")["cases"]
    require(len(annotation_cases) == 1024 and len(content_cases) == 73, "independent corpus count differs")
    for index, case in enumerate(annotation_cases):
        effects = {field: bool(index & (1 << bit)) for bit, field in enumerate(FIELDS)}
        require(exact(case["inputs"], {ENTRY_ANNOTATIONS: effects}), "complete ordered Boolean domain differs")
    names = []
    for case in content_cases:
        require(set(case["inputs"]) == {ENTRY_CONTENT} and type(case["inputs"][ENTRY_CONTENT]) is str,
                "content fixture input differs")
        names.append(case["inputs"][ENTRY_CONTENT])
    js = annotation + "\n" + content + "\nconst fields=" + json.dumps(FIELDS) + ";\nconst names=" + json.dumps(names) + ";\n"
    js += "const annotations=Array.from({length:1024},(_,i)=>annotationsFromEffects(Object.fromEntries(fields.map((f,b)=>[f,Boolean(i & (1<<b))]))));\n"
    js += "process.stdout.write(JSON.stringify({annotations,content:names.map(toolReturnsTargetContent)}));\n"
    result = subprocess.run(["node"], input=js.encode(), env=env, capture_output=True, timeout=10)
    require(result.returncode == 0, "isolated original pure functions failed")
    values = strict_json(result.stdout)
    require(len(values["annotations"]) == 1024 and len(values["content"]) == len(names), "original result roster differs")
    for entry, cases, outputs in ((ENTRY_ANNOTATIONS, annotation_cases, values["annotations"]),
                                   (ENTRY_CONTENT, content_cases, values["content"])):
        for case, actual in zip(cases, outputs):
            require(exact(case["expected"], {entry: actual}), "independent expectation differs from original function")
    return {"source_sha256": sha(source), "license_sha256": sha(license_bytes), "isolated_functions_sha256": sha(js.encode()),
            "annotations": {"cases": 1024, "matched": 1024, "scope": "Every assignment of the ten Boolean fields; all four outputs."},
            "content": {"cases": len(names), "matched": len(names), "scope": "Independent finite Text examples, not all Text values."},
            "scope": "Only two pure original functions and their exact constant set. TypeScript annotations/export removed. No full REA setup, registry resolver or target execution."}


def observe(compiler, go, out, env, pin, go_digest):
    records = []
    for name, workspace_name, cases_name, entry, expected_count in (
            ("annotations", "annotations.workspace.json", "annotations-cases.json", ENTRY_ANNOTATIONS, 1024),
            ("content", "content.workspace.json", "content-cases.json", ENTRY_CONTENT, 73),
            ("budget", "budget.workspace.json", "budget-cases.json", ENTRY_BUDGET, 218)):
        workspace, original_cases = EXAMPLE / workspace_name, EXAMPLE / "cases" / cases_name
        total = len(read(original_cases)["cases"])
        require(total == expected_count, "review changed finite corpus")
        offset, groups = 0, []
        for index, cases in enumerate(batches(original_cases, out, name)):
            label = name + f"-{index:03d}"
            receipt_path = out / (label + "-execution.json")
            raw = command([compiler, "package", "execute", "--json", "--go", go, "--cases", str(cases), str(workspace)], env)
            receipt_path.write_bytes(raw)
            receipt = strict_json(raw)
            runtime = receipts.validate(receipt, workspace, cases, entry, pin, go_digest, EXAMPLE)
            replay_raw = command([compiler, "package", "replay", "--json", "--go", go, "--receipt", str(receipt_path), "--cases", str(cases), str(workspace)], env)
            (out / (label + "-replay.json")).write_bytes(replay_raw)
            replay = strict_json(replay_raw)
            second = receipts.validate(replay, workspace, cases, entry, pin, go_digest, EXAMPLE)
            require(replay["replayed_from_sha256"] == sha(raw) and exact(runtime["traces"], second["traces"]) and
                    receipt["result"]["composition"]["source"] == replay["result"]["composition"]["source"] and
                    receipt["result"]["composition"]["driver_source"] == replay["result"]["composition"]["driver_source"] and
                    receipt["result"]["program"]["lowered_gooo_source"] == replay["result"]["program"]["lowered_gooo_source"],
                    "whole tool effects replay differs")
            rejected = receipts.mutation_checks(receipt, workspace, cases, entry, pin, go_digest, EXAMPLE)
            groups.append({"offset": offset, "cases": runtime["finite_total"], "passed": runtime["finite_passed"],
                           "whole_replay_equal": True, "native_execution_this_invocation": True,
                           "cases_sha256": sha(cases.read_bytes()), "execution_sha256": sha(raw), "replay_sha256": sha(replay_raw),
                           "rejected_receipt_mutations": rejected})
            offset += runtime["finite_total"]
            print(json.dumps({"batch": label, "cases": runtime["finite_total"], "passed": runtime["finite_passed"], "whole_replay_equal": True}), flush=True)
        require(offset == total, "not every independent fixture was observed")
        records.append({"name": name, "cases": total, "passed": offset, "whole_replay_equal": True,
                        "original_cases_sha256": sha(original_cases.read_bytes()), "batches": groups})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    require(not out.exists(), "use a fresh tool effects output directory")
    require(Path(args.compiler).is_absolute() or not args.compiler.startswith("-"), "invalid compiler path")
    require(Path(args.go).is_absolute(), "select the Go executable by absolute path")
    out.mkdir(parents=True)
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0"})
    pin = (EXAMPLE / "compiler-version.txt").read_text().strip()
    require(pin == PIN and pin == (PROJECT / "examples/evidence-admission/compiler-version.txt").read_text().strip(),
            "tool effects compiler differs from the separately pinned evidence compiler")
    identity = strict_json(command([args.compiler, "version", "--build", "--json"], env, 15))
    require(identity["compiler_source_sha"] == pin and identity["version"] == "0.6.32-dev" and identity["source_status"] == "CLEAN_VCS" and
            identity["vcs_modified"] == "false" and identity["go_version"] == "go1.27.2", "compiler identity differs")
    go_digest = sha(Path(args.go).read_bytes())
    reference = original_reference(env)
    report = {"schema": "policy-studio/tool-effects-observation/v1", "compiler": identity,
              "original_reference": reference, "runs": observe(args.compiler, args.go, out, env, pin, go_digest)}
    report["source_files"] = {str(p.relative_to(PROJECT)): sha(p.read_bytes()) for p in sorted(EXAMPLE.rglob("*")) if p.is_file()}
    report["verifier_files"] = {"tools/verify-tool-effects.py": sha(Path(__file__).read_bytes()),
                                "tools/verify-evidence-admission.py": sha((PROJECT / "tools/verify-evidence-admission.py").read_bytes())}
    report["scope"] = "Complete ten-Boolean domain for original annotations (1024); finite target-content (73) and original effect-budget (218) examples. All ordered inputs and complete outputs observed and replayed. Pure trusted-audit/policy projection, no tool execution, authentication, capability grant, sandbox, model call, remote exactly-once guarantee or all-input safety proof. Unsigned byte consistency; inner typed-plan/runtime-suite digests not independently recomputed."
    (out / "observations.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "cases": sum(r["cases"] for r in report["runs"]), "batches": sum(len(r["batches"]) for r in report["runs"]), "scope": report["scope"]}))


if __name__ == "__main__":
    main()
