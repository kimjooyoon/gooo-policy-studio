#!/usr/bin/env python3
"""Check exact portable asset bytes and finite observation bindings, without execution.

The checksums and provenance are unsigned consistency records, not publisher
authentication. --self-test uses synthetic files and never executes a binary.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path, PurePosixPath

SCHEMA = "policy-studio/portable-release/v1"
GO_VERSION = "go1.27.3"
GENERATION_GO_VERSION = "go1.27.3"
TARGETS = [("linux", "amd64"), ("linux", "arm64"),
           ("darwin", "amd64"), ("darwin", "arm64"), ("windows", "amd64")]
DATA_SOURCES = {
    "START-HERE.txt": "docs/START-HERE.txt",
    "bootstrap.json": "examples/automation-gate/bootstrap.json",
    "impact-input.json": "examples/automation-policy/impact-input.json",
    "generation.json": "evidence/generation.json",
    "LICENSE": "LICENSE",
    "Go-LICENSE": "licenses/Go-LICENSE",
}
GATE_PROOF = "machine-gate-proof-linux-amd64.json"
REPORT = "policy-check-report-linux-amd64.json"
REPLAY = "policy-check-replay-linux-amd64.json"
REQUIRED_SOURCES = set(DATA_SOURCES.values()) | {
    "go.mod", "tools/compiler-version.txt", "internal/policy/approval.gooo",
    "internal/policy/generated.txt", "internal/policy/bridge_generated.go",
    "internal/policy/generation.json", "tools/package-release.py",
    "tools/verify-release-assets.py", "tools/verify-machine-gate.py",
    ".github/workflows/ci.yml", ".github/workflows/release.yml",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}\Z")
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
SCOPE = ("Unsigned source and asset byte bindings; actual CGO-disabled Linux amd64 "
         "gate and policy-check observations on synthetic inputs. Other asset binaries "
         "are compile-only. No imported macOS observations, publisher authentication, "
         "external effects, or all-input safety proof.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def object_pairs(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "duplicate JSON property")
            out[key] = value
        return out
    def invalid_constant(_):
        raise ValueError("non-finite JSON number")
    return json.loads(raw.decode("utf-8", errors="strict"),
                      object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(exact(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def asset_specs():
    assets = {}
    for goos, goarch in TARGETS:
        components = ["policy-studio", "policy-check"]
        if goos != "windows":
            components.append("policy-gate")
        for component in components:
            name = f"{component}-{goos}-{goarch}" + (".exe" if goos == "windows" else "")
            runtime = "compile-only"
            if (goos, goarch) == ("linux", "amd64") and component in ("policy-gate", "policy-check"):
                runtime = "finite-release-binary-observed"
            assets[name] = {"kind": "binary", "component": component,
                            "goos": goos, "goarch": goarch, "runtime": runtime}
    for name in DATA_SOURCES:
        assets[name] = {"kind": "guide" if name == "START-HERE.txt" else "data"}
    for name in (GATE_PROOF, REPORT, REPLAY):
        assets[name] = {"kind": "observation"}
    return assets


def target_roster():
    return [{"goos": goos, "goarch": goarch,
             "components": ["policy-studio", "policy-check"] + ([] if goos == "windows" else ["policy-gate"])}
            for goos, goarch in TARGETS]


def check_binary(raw, goos, goarch):
    if goos == "linux":
        require(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64 asset")
        require(struct.unpack_from("<H", raw, 18)[0] == {"amd64": 62, "arm64": 183}[goarch], "ELF architecture differs")
        require(struct.unpack_from("<H", raw, 16)[0] in (2, 3), "ELF is not executable")
    elif goos == "darwin":
        require(len(raw) >= 32 and raw[:4] == b"\xcf\xfa\xed\xfe", "expected little-endian Mach-O64 asset")
        require(struct.unpack_from("<I", raw, 4)[0] == {"amd64": 0x1000007, "arm64": 0x100000C}[goarch], "Mach-O architecture differs")
        require(struct.unpack_from("<I", raw, 12)[0] == 2, "Mach-O is not executable")
    else:
        require(len(raw) >= 64 and raw[:2] == b"MZ", "expected Windows PE asset")
        offset = struct.unpack_from("<I", raw, 60)[0]
        require(offset + 26 <= len(raw) and raw[offset:offset + 4] == b"PE\0\0", "PE signature is absent")
        require(struct.unpack_from("<H", raw, offset + 4)[0] == 0x8664 and
                struct.unpack_from("<H", raw, offset + 24)[0] == 0x20B, "PE is not amd64 PE32+")


def source_inventory(project, commit):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(project), *args])
    require(git("rev-parse", "HEAD").decode().strip() == commit, "source checkout differs from release commit")
    require(subprocess.run(["git", "-C", str(project), "diff", "--quiet", "HEAD", "--"], check=False).returncode == 0,
            "tracked source checkout is modified")
    names = [name.decode("utf-8") for name in git("ls-files", "-z").split(b"\0") if name]
    inventory = {}
    for name in names:
        path = project / name
        require(path.is_file() and not path.is_symlink(), "source roster contains a nonregular file")
        inventory[name] = sha256(path.read_bytes())
    require(REQUIRED_SOURCES <= set(inventory), "required release source is not tracked")
    return inventory


def policy_provenance(sources, generation):
    compiler = generation["compiler"]["compiler_source_sha"]
    require(isinstance(compiler, str) and COMMIT.fullmatch(compiler), "compiler source identity is invalid")
    require(generation["schema"] == "policy-studio/generation/v1" and
            generation["compiler"]["go_version"] == GENERATION_GO_VERSION, "generation identity differs")
    require(sources["tools/compiler-version.txt"] == sha256((compiler + "\n").encode()), "compiler pin differs from generation")
    result = {"source_sha256": "sha256:" + sources["internal/policy/approval.gooo"],
              "generated_sha256": "sha256:" + sources["internal/policy/generated.txt"],
              "compiler_source_sha": compiler,
              "generation_sha256": "sha256:" + sources["internal/policy/generation.json"],
              "adapter_sha256": "sha256:" + sources["internal/policy/bridge_generated.go"]}
    for key in ("source_sha256", "generated_sha256", "adapter_sha256"):
        require(generation[key] == result[key], "generation source/code/adapter hash differs")
    require(sources["internal/policy/generation.json"] == sources["evidence/generation.json"], "embedded and published generation bytes differ")
    return result


def check_observations(raw_assets, manifest, provenance):
    proof = strict_json(raw_assets[GATE_PROOF])
    binary = "policy-gate-linux-amd64"
    require(proof["schema"] == "policy-studio/machine-gate-observation/v1" and proof["passed"] is True and
            type(proof["cases"]) is int and proof["cases"] == 12 and proof["raw_credentials_recorded"] is False and
            proof["binary_sha256"] == manifest["assets"][binary]["sha256"], "gate proof is not bound to the released binary")
    roster = [("missing_credential", 401), ("stale_policy", 409), ("caller_policy_override", 400),
              ("duplicate_JSON_key", 400), ("authenticated_Gooo_approval", 200), ("same_intent_retry", 200),
              ("key_reused_for_changed_intent", 409), ("stale_request_with_new_key", 409),
              ("Gooo_over_limit_denial", 403), ("second_process_writer", None),
              ("approved_retry_after_process_restart", 200), ("denied_retry_after_process_restart", 403)]
    require(len(proof["observations"]) == len(roster), "gate observation roster differs")
    for row, (name, status) in zip(proof["observations"], roster):
        require(row["case"] == name, "gate observation order differs")
        if status is not None:
            require(type(row["status"]) is int and row["status"] == status, "gate observed status differs")
        else:
            require(row["startup_rejected"] is True, "second writer was not rejected")
        if "retry" in name:
            require(row["same_outcome"] is True, "gate retry did not preserve the original outcome")
    require(exact(proof["final_request_states"], {"req-export-1": ["approved", 2], "req-export-over-limit": ["pending", 1]}), "gate final states differ")
    bootstrap = strict_json(raw_assets["bootstrap.json"])
    version_document = {"policy": bootstrap["policy"], "provenance": provenance}
    version = "sha256:" + sha256(json.dumps(version_document, separators=(",", ":")).encode())
    require(proof["policy_version"] == version, "gate policy version does not bind packaged rules and code")
    example = strict_json(raw_assets["impact-input.json"])
    require(len(example["cases"]) == 5, "release impact example must have five independently authored expectations")
    reports = [strict_json(raw_assets[name]) for name in (REPORT, REPLAY)]
    decision_fields = {"approved", "reason", "amount_ok", "team_ok", "reviewer_ok", "self_ok", "submitted_ok"}
    for report in reports:
        require(report["schema"] == "policy-studio/impact-report/v1" and exact(report["input"], example) and
                report["provenance"] == provenance and len(report["rows"]) == 5 and
                isinstance(report["id"], str) and SHA.fullmatch(report["id"]), "policy-check report input/code binding differs")
        checks = report["checks"]
        require(set(checks) == {"passed", "matched", "mismatched"} and checks["passed"] is True and
                type(checks["matched"]) is int and checks["matched"] == 5 and
                type(checks["mismatched"]) is int and checks["mismatched"] == 0, "policy-check did not match all five supplied expectations")
        require(type(report["summary"]["cases"]) is int and report["summary"]["cases"] == 5, "policy report case count differs")
        for row, case in zip(report["rows"], example["cases"]):
            receipt = row["receipt"]
            expected_input = {"request": case["request"], "reviewer": case["reviewer"], "before": example["before"], "after": example["after"]}
            require(row["id"] == case["id"] and row["expectation_matched"] is True and exact(receipt["input"], expected_input) and
                    exact(receipt["result"]["after"], case["expected_after"]), "policy report row/input/expectation differs")
            require(set(receipt["result"]["after"]) == decision_fields, "policy decision field roster differs")
            require(receipt["source_sha256"] == provenance["source_sha256"] and
                    receipt["generated_sha256"] == provenance["generated_sha256"] and
                    receipt["compiler_source_sha"] == provenance["compiler_source_sha"], "row provenance differs")
    original, replay = reports
    for key in ("input", "provenance", "summary", "checks", "corpus_sha256", "scope"):
        require(exact(original[key], replay[key]), "saved report replay changed a complete report binding")
    require(exact([r["receipt"]["result"] for r in original["rows"]], [r["receipt"]["result"] for r in replay["rows"]]), "saved report replay changed actual decisions")
    return {
        "gate": {"binary": binary, "binary_sha256": manifest["assets"][binary]["sha256"],
                 "proof": GATE_PROOF, "proof_sha256": sha256(raw_assets[GATE_PROOF]), "cases": 12, "passed": True},
        "policy_check": {"binary": "policy-check-linux-amd64", "binary_sha256": manifest["assets"]["policy-check-linux-amd64"]["sha256"],
                         "input_sha256": sha256(raw_assets["impact-input.json"]), "report_sha256": sha256(raw_assets[REPORT]),
                         "replay_sha256": sha256(raw_assets[REPLAY]), "cases": 5, "saved_replay": True, "passed": True},
    }


def verify_assets(directory, version, commit, project=None):
    require(VERSION.fullmatch(version) and COMMIT.fullmatch(commit), "version or source commit is invalid")
    specs = asset_specs()
    expected_names = set(specs) | {"provenance.json", "SHA256SUMS"}
    actual = {path.name for path in directory.iterdir()}
    require(actual == expected_names, "release asset inventory is incomplete or contains unexpected files")
    raw = {}
    for name in sorted(actual):
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "release assets must be regular files")
        raw[name] = path.read_bytes()
        require(raw[name], "release asset is empty")
    expected_sums = "".join(f"{sha256(raw[name])}  {name}\n" for name in sorted(actual - {"SHA256SUMS"}))
    require(raw["SHA256SUMS"] == expected_sums.encode(), "SHA256SUMS does not bind exact complete asset bytes")
    manifest = strict_json(raw["provenance.json"])
    require(set(manifest) == {"schema", "version", "source_commit", "go_version", "cgo_enabled", "build_flags", "targets", "source_bindings", "assets", "runtime_checks", "scope"}, "release provenance field roster differs")
    require(manifest["schema"] == SCHEMA and manifest["version"] == version and manifest["source_commit"] == commit and
            manifest["go_version"] == GO_VERSION and type(manifest["cgo_enabled"]) is int and manifest["cgo_enabled"] == 0 and
            manifest["build_flags"] == ["-trimpath", "-buildvcs=false"] and manifest["targets"] == target_roster() and manifest["scope"] == SCOPE, "release identity, target or observation scope differs")
    require(set(manifest["assets"]) == set(specs), "provenance asset roster differs")
    for name, spec in specs.items():
        require(exact(manifest["assets"][name], {**spec, "bytes": len(raw[name]), "sha256": sha256(raw[name])}), "provenance does not bind exact asset bytes: " + name)
        if spec["kind"] == "binary":
            check_binary(raw[name], spec["goos"], spec["goarch"])
    sources = manifest["source_bindings"]
    require(isinstance(sources, dict) and REQUIRED_SOURCES <= set(sources), "source binding roster is incomplete")
    for name, digest in sources.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and isinstance(digest, str) and HEX64.fullmatch(digest), "unsafe or invalid source binding")
    if project is not None:
        require(sources == source_inventory(project, commit), "complete tracked source bytes differ from provenance")
    for name, source in DATA_SOURCES.items():
        if name == "START-HERE.txt":
            require(b"@VERSION@" not in raw[name] and b"@COMMIT@" not in raw[name] and
                    version.encode() in raw[name] and commit.encode() in raw[name], "start guide has unresolved or wrong release identity")
            if project is not None:
                template = (project / source).read_bytes()
                require(raw[name] == template.replace(b"@VERSION@", version.encode()).replace(b"@COMMIT@", commit.encode()), "start guide differs from exact template expansion")
        else:
            require(sha256(raw[name]) == sources[source], "packaged example or generation bytes differ from source")
    provenance = policy_provenance(sources, strict_json(raw["generation.json"]))
    require(exact(manifest["runtime_checks"], check_observations(raw, manifest, provenance)), "runtime observation metadata differs from asset evidence")
    return {"passed": True, "assets": len(actual), "version": version, "source_commit": commit,
            "released_gate_cases": 12, "released_policy_check_cases": 5,
            "scope": "Asset byte/metadata checks; no binary was executed by this verifier."}


def self_test():
    class AssetTests(unittest.TestCase):
        def fixture(self, directory):
            version, commit = "v0.2.0-preview-test", "a" * 40
            specs = asset_specs()
            raw = {}
            for name, spec in specs.items():
                if spec["kind"] != "binary":
                    continue
                header = bytearray(128)
                if spec["goos"] == "linux":
                    header[:6] = b"\x7fELF\x02\x01"
                    struct.pack_into("<HH", header, 16, 2, {"amd64": 62, "arm64": 183}[spec["goarch"]])
                elif spec["goos"] == "darwin":
                    header[:4] = b"\xcf\xfa\xed\xfe"
                    struct.pack_into("<I", header, 4, {"amd64": 0x1000007, "arm64": 0x100000C}[spec["goarch"]])
                    struct.pack_into("<I", header, 12, 2)
                else:
                    header[:2] = b"MZ"
                    struct.pack_into("<I", header, 60, 64)
                    header[64:68] = b"PE\0\0"
                    struct.pack_into("<H", header, 68, 0x8664)
                    struct.pack_into("<H", header, 88, 0x20B)
                raw[name] = bytes(header) + name.encode()
            sources = {name: sha256(name.encode()) for name in REQUIRED_SOURCES}
            sources["tools/compiler-version.txt"] = sha256(("b" * 40 + "\n").encode())
            generation = {"schema": "policy-studio/generation/v1", "compiler": {"compiler_source_sha": "b" * 40, "go_version": GENERATION_GO_VERSION},
                          "source_sha256": "sha256:" + sources["internal/policy/approval.gooo"],
                          "generated_sha256": "sha256:" + sources["internal/policy/generated.txt"],
                          "adapter_sha256": "sha256:" + sources["internal/policy/bridge_generated.go"]}
            raw["generation.json"] = json.dumps(generation).encode()
            sources["evidence/generation.json"] = sources["internal/policy/generation.json"] = sha256(raw["generation.json"])
            rules = {"limit": 1000000, "same_team": True, "active_reviewer": True, "prevent_self": True}
            bootstrap = {"policy": rules}
            raw["bootstrap.json"] = json.dumps(bootstrap).encode()
            expected = {"approved": True, "reason": "APPROVED", "amount_ok": True, "team_ok": True, "reviewer_ok": True, "self_ok": True, "submitted_ok": True}
            example = {"schema": "policy-studio/impact-input/v1", "before": rules, "after": rules,
                       "cases": [{"id": f"fixture-{i}", "request": {"key": f"fixture-{i}"}, "reviewer": {"key": "fixture"}, "expected_after": expected} for i in range(5)]}
            raw["impact-input.json"] = json.dumps(example).encode()
            raw["START-HERE.txt"] = f"Synthetic helper test only {version} {commit}\n".encode()
            for name in ("LICENSE", "Go-LICENSE"):
                raw[name] = f"Synthetic helper fixture {name}\n".encode()
                sources[DATA_SOURCES[name]] = sha256(raw[name])
            for name in ("bootstrap.json", "impact-input.json"):
                sources[DATA_SOURCES[name]] = sha256(raw[name])
            provenance = policy_provenance(sources, generation)
            rows = [{"id": case["id"], "expectation_matched": True, "receipt": {
                "input": {"request": case["request"], "reviewer": case["reviewer"], "before": rules, "after": rules},
                "result": {"after": expected}, "source_sha256": provenance["source_sha256"],
                "generated_sha256": provenance["generated_sha256"], "compiler_source_sha": provenance["compiler_source_sha"]}} for case in example["cases"]]
            report = {"schema": "policy-studio/impact-report/v1", "id": "sha256:" + "c" * 64, "input": example,
                      "provenance": provenance, "rows": rows, "checks": {"passed": True, "matched": 5, "mismatched": 0},
                      "summary": {"cases": 5}, "corpus_sha256": "sha256:" + "d" * 64, "scope": "synthetic helper fixture"}
            raw[REPORT] = raw[REPLAY] = json.dumps(report).encode()
            observations = [{"case": name, **({"status": status} if status is not None else {"startup_rejected": True}),
                             **({"same_outcome": True} if "retry" in name else {})} for name, status in [
                ("missing_credential", 401), ("stale_policy", 409), ("caller_policy_override", 400), ("duplicate_JSON_key", 400),
                ("authenticated_Gooo_approval", 200), ("same_intent_retry", 200), ("key_reused_for_changed_intent", 409),
                ("stale_request_with_new_key", 409), ("Gooo_over_limit_denial", 403), ("second_process_writer", None),
                ("approved_retry_after_process_restart", 200), ("denied_retry_after_process_restart", 403)]]
            proof = {"schema": "policy-studio/machine-gate-observation/v1", "passed": True, "cases": 12,
                     "raw_credentials_recorded": False, "binary_sha256": sha256(raw["policy-gate-linux-amd64"]),
                     "policy_version": "sha256:" + sha256(json.dumps({"policy": rules, "provenance": provenance}, separators=(",", ":")).encode()),
                     "observations": observations, "final_request_states": {"req-export-1": ["approved", 2], "req-export-over-limit": ["pending", 1]}}
            raw[GATE_PROOF] = json.dumps(proof).encode()
            manifest = {"schema": SCHEMA, "version": version, "source_commit": commit, "go_version": GO_VERSION,
                        "cgo_enabled": 0, "build_flags": ["-trimpath", "-buildvcs=false"], "targets": target_roster(),
                        "source_bindings": sources, "assets": {name: {**spec, "bytes": len(raw[name]), "sha256": sha256(raw[name])} for name, spec in specs.items()}, "scope": SCOPE}
            manifest["runtime_checks"] = check_observations(raw, manifest, provenance)
            raw["provenance.json"] = json.dumps(manifest).encode()
            for name, content in raw.items():
                (directory / name).write_bytes(content)
            self.sums(directory)
            return version, commit

        def sums(self, directory):
            names = sorted(path.name for path in directory.iterdir() if path.name != "SHA256SUMS")
            (directory / "SHA256SUMS").write_text("".join(f"{sha256((directory / name).read_bytes())}  {name}\n" for name in names))

        def test_synthetic_fixture(self):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                version, commit = self.fixture(directory)
                self.assertTrue(verify_assets(directory, version, commit)["passed"])

        def test_mutations_rejected_even_when_checksums_are_rewritten(self):
            for mutation in ("missing-target", "missing-license", "extra-windows-gate", "changed-bytes", "wrong-architecture", "stale-gate-proof", "mismatched-case", "Boolean-number-alias", "gate-revision-Boolean-alias", "asset-byte-float-alias", "runtime-case-float-alias", "runtime-passed-integer-alias", "runtime-replay-integer-alias", "runtime-overclaim", "wrong-version", "duplicate-manifest", "symlink", "bad-checksum"):
                with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    version, commit = self.fixture(directory)
                    manifest_path = directory / "provenance.json"
                    manifest = strict_json(manifest_path.read_bytes())
                    name = "policy-studio-darwin-arm64"
                    if mutation == "missing-target": (directory / name).unlink()
                    elif mutation == "missing-license": (directory / "Go-LICENSE").unlink()
                    elif mutation == "extra-windows-gate": (directory / "policy-gate-windows-amd64.exe").write_bytes(b"unexpected")
                    elif mutation == "changed-bytes": (directory / name).write_bytes((directory / name).read_bytes() + b"changed")
                    elif mutation == "wrong-architecture":
                        changed = bytearray((directory / name).read_bytes())
                        struct.pack_into("<I", changed, 4, 0x1000007)
                        (directory / name).write_bytes(changed)
                        manifest["assets"][name]["sha256"] = sha256(changed)
                    elif mutation == "stale-gate-proof":
                        proof = strict_json((directory / GATE_PROOF).read_bytes())
                        proof["binary_sha256"] = "0" * 64
                        (directory / GATE_PROOF).write_text(json.dumps(proof))
                        manifest["assets"][GATE_PROOF].update(bytes=(directory / GATE_PROOF).stat().st_size, sha256=sha256((directory / GATE_PROOF).read_bytes()))
                    elif mutation == "gate-revision-Boolean-alias":
                        proof = strict_json((directory / GATE_PROOF).read_bytes())
                        proof["final_request_states"]["req-export-over-limit"][1] = True
                        (directory / GATE_PROOF).write_text(json.dumps(proof))
                        digest = sha256((directory / GATE_PROOF).read_bytes())
                        manifest["assets"][GATE_PROOF].update(bytes=(directory / GATE_PROOF).stat().st_size, sha256=digest)
                        manifest["runtime_checks"]["gate"]["proof_sha256"] = digest
                    elif mutation == "asset-byte-float-alias": manifest["assets"][name]["bytes"] = float(manifest["assets"][name]["bytes"])
                    elif mutation == "runtime-case-float-alias": manifest["runtime_checks"]["gate"]["cases"] = 12.0
                    elif mutation == "runtime-passed-integer-alias": manifest["runtime_checks"]["gate"]["passed"] = 1
                    elif mutation == "runtime-replay-integer-alias": manifest["runtime_checks"]["policy_check"]["saved_replay"] = 1
                    elif mutation in ("mismatched-case", "Boolean-number-alias"):
                        report = strict_json((directory / REPORT).read_bytes())
                        if mutation == "mismatched-case": report["rows"][0]["expectation_matched"] = False
                        else: report["rows"][0]["receipt"]["result"]["after"]["approved"] = 1
                        (directory / REPORT).write_text(json.dumps(report))
                        manifest["assets"][REPORT].update(bytes=(directory / REPORT).stat().st_size, sha256=sha256((directory / REPORT).read_bytes()))
                    elif mutation == "runtime-overclaim": manifest["assets"][name]["runtime"] = "finite-release-binary-observed"
                    elif mutation == "wrong-version": manifest["version"] = "v0.1.0"
                    elif mutation == "symlink":
                        (directory / name).unlink()
                        (directory / name).symlink_to(directory / "policy-studio-darwin-amd64")
                    manifest_path.write_text(json.dumps(manifest))
                    if mutation == "duplicate-manifest": manifest_path.write_bytes(b'{"schema":"discarded",' + manifest_path.read_bytes()[1:])
                    self.sums(directory)
                    if mutation == "bad-checksum": (directory / "SHA256SUMS").write_text("0" * 64 + "  provenance.json\n")
                    with self.assertRaises((ValueError, KeyError)):
                        verify_assets(directory, version, commit)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AssetTests))
    require(result.wasSuccessful(), "release helper fixture checks failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist")
    parser.add_argument("--version")
    parser.add_argument("--commit")
    parser.add_argument("--source")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print(json.dumps({"passed": True, "scope": "Synthetic helper fixtures only; no release binary execution."}))
        return
    parser.error("provide --dist, --version and --commit") if not (args.dist and args.version and args.commit) else None
    print(json.dumps(verify_assets(Path(args.dist), args.version, args.commit, Path(args.source).resolve() if args.source else None)))


if __name__ == "__main__":
    main()
