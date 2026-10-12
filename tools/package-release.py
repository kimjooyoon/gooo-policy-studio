#!/usr/bin/env python3
"""Build and observe the exact portable release assets with the existing Go toolchain.

All temporary state, credentials, subprocess environments and build outputs are
owned by this invocation. No global environment or HOME value is reassigned.
"""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_asset_checks", PROJECT / "tools/verify-release-assets.py")
ASSETS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASSETS)


def build_environment(goos=None, goarch=None):
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "",
                "CGO_ENABLED": "0", "GOPROXY": "off", "GOSUMDB": "off"})
    # Toolchain identity queries must describe this runner, even if its caller
    # has set cross-compilation variables. Builds select each explicit target.
    for name in ("GOOS", "GOARCH"):
        env.pop(name, None)
    if goos is not None:
        env["GOOS"], env["GOARCH"] = goos, goarch
    return env


def run(command, env, timeout=180):
    result = subprocess.run(command, cwd=PROJECT, env=env, capture_output=True, timeout=timeout)
    if result.returncode != 0:
        # Policy inputs and helper observations are synthetic. Gate failures
        # still use a generic diagnostic so generated credentials cannot leak.
        raise ValueError("release command failed: " + Path(command[0]).name)
    return result.stdout


def package(directory, version, commit):
    ASSETS.require(ASSETS.VERSION.fullmatch(version) and ASSETS.COMMIT.fullmatch(commit), "invalid release version or commit")
    ASSETS.require(not directory.exists() and not directory.is_symlink(), "release output directory must be new")
    sources = ASSETS.source_inventory(PROJECT, commit)
    env = build_environment()
    ASSETS.require(run(["go", "env", "GOVERSION"], env).decode().strip() == ASSETS.GO_VERSION, "use the already installed pinned Go toolchain")
    tool_target = run(["go", "env", "GOOS", "GOARCH"], env).decode().split()
    ASSETS.require(tool_target == ["linux", "amd64"], "release packaging observations require a Linux amd64 runner")
    goroot = Path(run(["go", "env", "GOROOT"], env).decode().strip())
    ASSETS.require((goroot / "LICENSE").read_bytes() == (PROJECT / "licenses/Go-LICENSE").read_bytes(), "preserved Go license differs from the selected pinned toolchain")
    with tempfile.TemporaryDirectory(prefix="policy-release-build-") as temporary:
        staged = Path(temporary)
        specs = ASSETS.asset_specs()
        for name, spec in specs.items():
            if spec["kind"] != "binary":
                continue
            entry = {"policy-studio": "./cmd/server", "policy-check": "./cmd/policy-check", "policy-gate": "./cmd/policy-gate"}[spec["component"]]
            run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(staged / name), entry],
                build_environment(spec["goos"], spec["goarch"]))
        for name, source in ASSETS.DATA_SOURCES.items():
            raw = (PROJECT / source).read_bytes()
            if name == "START-HERE.txt":
                raw = raw.replace(b"@VERSION@", version.encode()).replace(b"@COMMIT@", commit.encode())
            (staged / name).write_bytes(raw)
        # -I ignores PYTHONOPTIMIZE and other Python configuration: the existing
        # gate helper's actual assertions remain enabled for the shipped binary.
        run([sys.executable, "-I", str(PROJECT / "tools/verify-machine-gate.py"),
             "--binary", str(staged / "policy-gate-linux-amd64"), "--out", str(staged / ASSETS.GATE_PROOF)], env, 90)
        policy_binary = str(staged / "policy-check-linux-amd64")
        report = run([policy_binary, "--input", str(staged / "impact-input.json")], env, 30)
        (staged / ASSETS.REPORT).write_bytes(report)
        replay = run([policy_binary, "--replay", "--input", str(staged / ASSETS.REPORT)], env, 30)
        (staged / ASSETS.REPLAY).write_bytes(replay)
        raw = {name: (staged / name).read_bytes() for name in specs}
        provenance = ASSETS.policy_provenance(sources, ASSETS.strict_json(raw["generation.json"]))
        manifest = {"schema": ASSETS.SCHEMA, "version": version, "source_commit": commit,
                    "go_version": ASSETS.GO_VERSION, "cgo_enabled": 0,
                    "build_flags": ["-trimpath", "-buildvcs=false"], "targets": ASSETS.target_roster(),
                    "source_bindings": sources,
                    "assets": {name: {**spec, "bytes": len(raw[name]), "sha256": ASSETS.sha256(raw[name])} for name, spec in specs.items()},
                    "runtime_checks": ASSETS.check_observations(raw, {"assets": {name: {"sha256": ASSETS.sha256(content)} for name, content in raw.items()}}, provenance),
                    "scope": ASSETS.SCOPE}
        (staged / "provenance.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        names = sorted(path.name for path in staged.iterdir())
        (staged / "SHA256SUMS").write_text("".join(f"{ASSETS.sha256((staged / name).read_bytes())}  {name}\n" for name in names), encoding="ascii")
        # Validate every complete byte binding before exposing the output and
        # recheck the source snapshot after all build and runtime commands.
        ASSETS.verify_assets(staged, version, commit, PROJECT)
        directory.mkdir(parents=True, exist_ok=False)
        for name in sorted(path.name for path in staged.iterdir()):
            shutil.copy2(staged / name, directory / name)
    return ASSETS.verify_assets(directory, version, commit, PROJECT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dist")
    parser.add_argument("--version")
    parser.add_argument("--commit")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        before = dict(os.environ)
        linux = build_environment("linux", "amd64")
        windows = build_environment("windows", "amd64")
        ASSETS.require(dict(os.environ) == before and linux["CGO_ENABLED"] == "0" and windows["GOOS"] == "windows", "build environment changed caller state")
        ASSETS.require(linux.get("HOME") == before.get("HOME"), "build environment changed HOME")
        ASSETS.self_test()
        print(json.dumps({"passed": True, "scope": "Synthetic asset/helper checks only; no Go build, binary execution or network."}))
        return
    if not args.version or not args.commit:
        parser.error("provide --version and --commit")
    print(json.dumps(package(Path(args.out).resolve(), args.version, args.commit)))


if __name__ == "__main__":
    main()
