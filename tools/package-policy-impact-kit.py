#!/usr/bin/env python3
"""Copy an existing policy-impact executable and committed public sources.

No Go, product, network, release helper, or compiler is invoked. git is used
only to read a clean tracked commit. This is assembly, not build provenance.
"""
import argparse
import hashlib
import io
import json
import os
import re
import selectors
import stat
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

MAX_BINARY = 64 << 20
MAX_FILE = 16 << 20
MAX_SOURCE = 128 << 20
MAX_ARCHIVE = 256 << 20
MAX_MEMBERS = 4096
MODULE = "github.com/kimjooyoon/gooo-policy-studio"
ROOT = "policy-impact-kit/"
SEEDS = ("case.json", "artifact.json", "policy-internal.json", "policy-external.json")
BOUNDS_SEEDS = ("case-row-501.json", "artifact-row-501.json", "policy-before-upper-1000.json", "policy-after-upper-500.json")
BOUNDS_DOCS = ("artifact-bounds-first-use.md", "artifact-int64-bounds.md", "artifact-policy-explain.md", "artifact-policy-impact.md", "artifact-policy-replay.md")
MAGIC = b"\xff Go buildinf:"


class Invalid(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Invalid(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_path(name):
    return (isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9._/-]+", name))
            and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")))


def read_regular(path, cap):
    """Bounded no-follow/nonblocking read, with path and descriptor identity."""
    path = Path(path)
    a = path.lstat()
    need(stat.S_ISREG(a.st_mode) and a.st_size <= cap, "INPUT_NOT_REGULAR_OR_BOUNDED")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        b = os.fstat(fd)
        need(stat.S_ISREG(b.st_mode) and os.path.samestat(a, b), "INPUT_CHANGED")
        chunks, count = [], 0
        while count <= cap:
            part = os.read(fd, min(1 << 20, cap + 1 - count))
            if not part:
                break
            chunks.append(part)
            count += len(part)
        c, d = os.fstat(fd), path.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(count <= cap and signature(a) == signature(b) == signature(c) == signature(d), "INPUT_CHANGED")
        return b"".join(chunks)
    finally:
        os.close(fd)


def text_json(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()


def varstring(raw, start):
    size, shift, pos = 0, 0, start
    for _ in range(10):
        need(pos < len(raw), "BUILDINFO_INVALID")
        b = raw[pos]
        pos += 1
        size |= (b & 127) << shift
        if b < 128:
            need(size <= 1 << 20 and pos + size <= len(raw), "BUILDINFO_INVALID")
            return raw[pos:pos + size], pos + size
        shift += 7
    raise Invalid("BUILDINFO_INVALID")


def parse_rows(go_version, rows):
    parsed = {"go_version": go_version, "path": "", "module": "", "module_version": "", "settings": {}}
    seen = set()
    for row in rows.splitlines():
        parts = row.split("\t")
        if parts[0] == "path":
            need(len(parts) == 2 and "path" not in seen, "BUILDINFO_INVALID")
            parsed["path"] = parts[1]
            seen.add("path")
        elif parts[0] == "mod":
            need(len(parts) in (3, 4) and "mod" not in seen, "BUILDINFO_INVALID")
            need(len(parts) == 3 or parts[3] == "", "EXTERNAL_MODULE_CHECKSUM_UNEXPECTED")
            parsed["module"], parsed["module_version"] = parts[1:3]
            seen.add("mod")
        elif parts[0] == "build":
            need(len(parts) == 2 and "=" in parts[1], "BUILDINFO_INVALID")
            key, value = parts[1].split("=", 1)
            need(key not in parsed["settings"] and bool(key), "BUILDINFO_INVALID")
            parsed["settings"][key] = value
        else:
            raise Invalid("BUILDINFO_UNEXPECTED_ROW")
    need(parsed["go_version"] == "go1.27.2" and parsed["path"] == MODULE + "/cmd/policy-impact"
         and parsed["module"] == MODULE, "BUILDINFO_WRONG_PROGRAM_OR_GO")
    s = parsed["settings"]
    need(s.get("-buildmode") == "exe" and s.get("-compiler") == "gc"
         and s.get("-trimpath") == "true" and s.get("CGO_ENABLED") in ("0", "1")
         and s.get("vcs") == "git" and bool(re.fullmatch(r"[0-9a-f]{40}", s.get("vcs.revision", "")))
         and s.get("vcs.modified") in ("true", "false"), "BUILDINFO_REQUIRED_SETTINGS")
    return parsed


def embedded_build(raw, target):
    """Go1.18+ inline buildinfo; structure from debug/buildinfo in Go1.27.2.

    This checks the bytes themselves rather than trusting supplied go-version-m
    text. It deliberately supports just the two frozen 64-bit little-endian
    executable formats, not a general executable loader.
    """
    if target == "darwin/arm64":
        need(len(raw) >= 32 and raw[:4] == b"\xcf\xfa\xed\xfe"
             and struct.unpack_from("<I", raw, 4)[0] == 0x0100000C
             and struct.unpack_from("<I", raw, 12)[0] == 2, "BINARY_TARGET_INVALID")
    elif target == "linux/amd64":
        need(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01"
             and struct.unpack_from("<H", raw, 18)[0] == 62
             and struct.unpack_from("<H", raw, 16)[0] in (2, 3), "BINARY_TARGET_INVALID")
    else:
        raise Invalid("TARGET_UNSUPPORTED")
    records = []
    pos = raw.find(MAGIC)
    while pos >= 0:
        if pos % 16 == 0 and pos + 32 < len(raw) and raw[pos + 14:pos + 16] == b"\x08\x02":
            try:
                version, end = varstring(raw, pos + 32)
                framed, _ = varstring(raw, end)
                need(len(framed) >= 33 and framed[-17] == 10
                     and framed[:16] == bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
                     and framed[-16:] == bytes.fromhex("f932433186182072008242104116d8f2"), "BUILDINFO_INVALID")
                records.append(parse_rows(version.decode("utf-8", "strict"), framed[16:-16].decode("utf-8", "strict")))
            except (Invalid, UnicodeError):
                pass
        pos = raw.find(MAGIC, pos + 1)
    need(len(records) == 1, "BUILDINFO_NOT_UNIQUE")
    record = records[0]
    need(record["settings"].get("GOOS", "") + "/" + record["settings"].get("GOARCH", "") == target, "BUILDINFO_TARGET_INVALID")
    return record


def supplied_build(raw):
    text = raw.decode("utf-8", "strict")
    lines = text.splitlines()
    need(lines and re.fullmatch(r"[^\r\n]+: go1\.27\.2", lines[0]), "BUILDINFO_TEXT_INVALID")
    need(all(line.startswith("\t") for line in lines[1:]), "BUILDINFO_TEXT_INVALID")
    rows = "\n".join(line[1:] for line in lines[1:]) + "\n"
    parsed = parse_rows("go1.27.2", rows)
    # Only the executable label is normalized: actual module/build rows survive.
    normalized = ("policy-impact: go1.27.2\n" + "\n".join(lines[1:]) + "\n").encode()
    return parsed, normalized


def git(repo, *args, cap=MAX_SOURCE):
    process = subprocess.Popen(["git", "-C", str(repo), *args], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks, size = [], 0
    try:
        while selector.get_map():
            need(bool(selector.select(timeout=30)), "SOURCE_GIT_READ_TIMEOUT")
            part = os.read(process.stdout.fileno(), min(65536, cap + 1 - size))
            if not part:
                selector.unregister(process.stdout)
                break
            size += len(part)
            need(size <= cap, "SOURCE_GIT_READ_BOUNDS")
            chunks.append(part)
        need(process.wait(timeout=30) == 0, "SOURCE_GIT_READ_FAILED")
        return b"".join(chunks)
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def source_snapshot(repo, ref):
    need(bool(re.fullmatch(r"[0-9a-f]{40}", ref)), "SOURCE_REF_INVALID")
    need(git(repo, "rev-parse", "HEAD", cap=128).decode().strip() == ref, "SOURCE_REF_NOT_HEAD")
    # CI can create untracked out/ proofs. Only tracked inputs must be clean;
    # archive reads the commit, never these untracked files or ignored binaries.
    need(not git(repo, "diff", "--name-only", "HEAD", "--", cap=1 << 20), "SOURCE_TRACKED_DIRTY")
    tree = git(repo, "rev-parse", ref + "^{tree}", cap=128).decode().strip()
    need(bool(re.fullmatch(r"[0-9a-f]{40}", tree)), "SOURCE_TREE_INVALID")
    archive = git(repo, "archive", "--format=tar", ref)
    result, modes, total = {}, {}, 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for entry in tar:
            name = entry.name.rstrip("/")
            need(safe_path(name), "SOURCE_PATH_INVALID")
            if entry.isdir():
                continue
            need(entry.isfile() and name not in result and entry.size <= MAX_FILE, "SOURCE_MEMBER_INVALID")
            need(not any(p in (".git", ".tools", "node_modules", "toolchain", "output", "bin", "out", "dist") for p in name.split("/")), "SOURCE_PRIVATE_OR_BINARY_PATH")
            stream = tar.extractfile(entry)
            need(stream is not None, "SOURCE_MEMBER_INVALID")
            raw = stream.read(MAX_FILE + 1)
            need(len(raw) == entry.size, "SOURCE_MEMBER_INVALID")
            total += len(raw)
            need(total <= MAX_SOURCE and len(result) < MAX_MEMBERS, "SOURCE_TOO_LARGE")
            result[name], modes[name] = raw, 0o755 if entry.mode & 0o111 else 0o644
    need(result and "go.mod" in result and result["go.mod"] == ("module " + MODULE + "\n\ngo 1.27.2\n").encode(), "SOURCE_MODULE_INVALID")
    return tree, result, modes


NOTICE = b"""Policy Impact experimental first-use kit

Gooo is an independent language project; this kit uses source-bound compiled
Gooo relations and Go host I/O/JSON. Google does not endorse this project.
Project code: MIT (LICENSE). Go runtime: BSD (Go-LICENSE). Rea-derived rule
materials: morluto MIT (LICENSE-REA). Complete notices are preserved here and
in the pinned source snapshot.

Assembly copies an existing binary. Its actual Go/VCS/CGO settings are in
buildinfo.txt and manifest.json. Package source commit is a separate record;
dirty or older VCS metadata is not a clean-main/tag or reproducible build claim.
Hashes provide byte consistency, not authenticated publisher provenance.

macOS: no Developer ID signing or notarization is claimed. The reused build
has CGO_ENABLED=1 and may use system dynamic libraries. Prior observed host
26.5.2 and load stamp 13.0 do not establish a tested minimum macOS version.
Browser-download quarantine behavior is untested; no protections are bypassed.

Only darwin/arm64 and linux/amd64 kit targets are defined. Historical replay
requires matching compiled sources, Go version and platform. Simulation and
unsigned historical consistency do not authorize current execution or prove
artifact issuer authenticity, external effects, adoption or universal safety.
"""

BOUNDS_NOTICE = b"""Policy Impact numeric bounds experimental first-use kit

Gooo is an independent language project; Google does not endorse this project.
Compiled Gooo rules judge numeric bounds; Go provides host I/O and JSON.
Project: MIT (LICENSE). Go runtime: BSD (Go-LICENSE). Rea-derived materials:
morluto MIT (LICENSE-REA). All notices and the committed source are included.

This assembly copies an existing executable and preserves actual Go/VCS/CGO
metadata. Dirty or older binary revision is not a clean package/tag build.
The package source commit is separate. Embedded source bytes and unsigned
hashes check consistency, not publisher signature or instruction equivalence.

macOS Developer ID signing, notarization, a minimum runtime and browser-download
quarantine behavior have not been established. No protections are bypassed.
Inspect actual CGO settings; this is not a static-binary claim. Linux execution
is checked on the repository Ubuntu CI runner, not other distributions or musl.

Only darwin/arm64 and linux/amd64 are defined. Historical replay requires matching
source/runtime/platform. Compare/replay/explain are local simulations, not a
current execution grant, authenticated history or artifact issuer proof. The
private HTML contains selected values. No production, adoption or universal
safety claim is made. Three CLI calls do not measure native or host-clock calls.
"""


def bounds_linkage(binary, source):
    """Source-material presence only, not exact embedded-variable linkage.

    Only the connected policy-impact runtime packages are in this finite roster.
    Presence does not map binary symbols/pointers, prove compiled instructions,
    or authenticate code. Tests, CLI handling and tool sources are outside this
    check; the optional three-call observation checks finite behavior.
    """
    packages = ("internal/artifactimpact/", "internal/artifactpreflight/", "internal/artifactnumeric/",
                "internal/jsoninput/", "internal/policy/", "internal/completion/", "internal/machinerules/")
    selected = set()
    for path, raw in source.items():
        if not path.startswith(packages) or not path.endswith(".go") or path.endswith("_test.go"):
            continue
        parent = path.rsplit("/", 1)[0] + "/"
        for line in raw.decode("utf-8", "strict").splitlines():
            if line.startswith("//go:embed "):
                for pattern in line[len("//go:embed "):].split():
                    directory_glob = pattern.endswith("/*")
                    selected_pattern = pattern[:-2] if directory_glob else pattern
                    need(safe_path(selected_pattern), "EMBED_PATTERN_UNSUPPORTED")
                    name = parent + selected_pattern
                    if name in source:
                        need(not directory_glob, "EMBED_PATTERN_UNSUPPORTED")
                        selected.add(name)
                    else:
                        matches = {n for n in source if n.startswith(name + "/")}
                        need(bool(matches), "EMBED_SOURCE_MISSING")
                        selected.update(matches)
    need(bool(selected), "EMBED_ROSTER_EMPTY")
    rows = []
    for name in sorted(selected):
        raw = source[name]
        need(bool(raw) and raw in binary, "BINARY_EMBED_SOURCE_MISMATCH")
        rows.append({"path": name, "bytes": len(raw), "sha256": sha(raw)})
    return {"method": "source_material_presence/v1", "authenticated": False,
            "CLI_argument_handling_bound": False, "sources": rows}


def assemble(args):
    bounds = getattr(args, "profile", "equality") == "bounds"
    repo = Path(args.repo).resolve(strict=True)
    before = read_regular(args.binary, MAX_BINARY)
    build, normalized = supplied_build(read_regular(args.buildinfo, 1 << 20))
    actual = embedded_build(before, args.target)
    need(build == actual, "BUILDINFO_TEXT_DOES_NOT_MATCH_BINARY")
    tree, source, source_modes = source_snapshot(repo, args.source_ref)
    payload = {"bin/policy-impact": before, "buildinfo.txt": normalized,
               "target.txt": (args.target + "\n").encode(), "notices/NOTICE.md": BOUNDS_NOTICE if bounds else NOTICE}
    modes = {name: 0o644 for name in payload}
    modes["bin/policy-impact"] = 0o755
    for name in BOUNDS_SEEDS if bounds else SEEDS:
        path = ("examples/artifact-int64-bounds/" if bounds else "examples/artifact-impact/") + name
        need(path in source, "SOURCE_SEED_MISSING")
        payload["seeds/" + name] = source[path]
    for name in BOUNDS_DOCS if bounds else ("policy-impact-first-use.md", "artifact-policy-impact.md", "artifact-policy-replay.md"):
        need("docs/" + name in source, "SOURCE_DOC_MISSING")
        payload["docs/" + name] = source["docs/" + name]
    demo_path = "examples/artifact-int64-bounds/try-demo.sh" if bounds else "examples/artifact-impact/try-demo.sh"
    need(demo_path in source, "SOURCE_DEMO_MISSING")
    payload["try-demo.sh"] = source[demo_path]
    modes["try-demo.sh"] = 0o755
    for original, name in (("LICENSE", "LICENSE"), ("licenses/Go-LICENSE", "Go-LICENSE"), ("internal/machinerules/assets/LICENSE-REA", "LICENSE-REA")):
        need(original in source, "SOURCE_LICENSE_MISSING")
        payload["notices/" + name] = source[original]
    for name, raw in source.items():
        payload["source/" + name] = raw
        modes["source/" + name] = source_modes[name]
    for name in payload:
        modes.setdefault(name, 0o644)
    row = lambda name, raw, mode: {"path": name, "mode": format(mode, "04o"), "bytes": len(raw), "sha256": sha(raw)}
    manifest = {"schema": "policy-impact-kit/v1", "target": args.target,
                "source": {"commit": args.source_ref, "tree": tree,
                           "tracked_files": [row(n, source[n], source_modes[n]) for n in sorted(source)]},
                "binary": {"bytes": len(before), "sha256": sha(before), "build": actual},
                "payload": [row(n, payload[n], modes[n]) for n in sorted(payload)],
                "assembly": {"copy_only": True, "product_calls": 0, "builds": 0, "network_calls": 0,
                             "build_revision_is_package_source_commit": actual["settings"]["vcs.revision"] == args.source_ref,
                             "binary_source_linkage": "Package snapshot and embedded source identities must be reviewed independently; VCS metadata is preserved, not rewritten."},
                "scope": "Experimental finite local simulation and unsigned same-implementation historical replay; no current execution grant or publisher authentication.",
                "limitations": {"macos_developer_id_or_notarization_claimed": False, "download_quarantine_tested": False,
                                "minimum_macos_runtime_verified": False, "portable_historical_replay": False,
                                "binary_was_rebuilt_during_assembly": False}}
    if bounds:
        manifest["schema"] = "policy-impact-kit/v2"
        manifest["profile"] = "artifact-bounds/v1"
        manifest["binary_source_bindings"] = bounds_linkage(before, source)
    payload["manifest.json"], modes["manifest.json"] = text_json(manifest), 0o644
    payload["SHA256SUMS"] = ("".join(sha(payload[n]) + "  " + n + "\n" for n in sorted(payload))).encode()
    modes["SHA256SUMS"] = 0o644
    need(len(payload) <= MAX_MEMBERS and sum(map(len, payload.values())) <= MAX_ARCHIVE, "KIT_TOO_LARGE")
    out = Path(args.out_dir)
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    out.chmod(0o700)
    filename = ("policy-impact-bounds-" if bounds else "policy-impact-") + args.target.replace("/", "-") + ".zip"
    destination = out / filename
    with destination.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=False) as archive:
            for name in sorted(payload):
                need(safe_path(name), "KIT_PATH_INVALID")
                info = zipfile.ZipInfo(ROOT + name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | modes[name]) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, payload[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        stream.flush()
        os.fsync(stream.fileno())
    after = read_regular(args.binary, MAX_BINARY)
    need(before == after, "BINARY_CHANGED_DURING_ASSEMBLY")
    final_tree, final_source, final_modes = source_snapshot(repo, args.source_ref)
    need((tree, source, source_modes) == (final_tree, final_source, final_modes), "SOURCE_CHANGED_DURING_ASSEMBLY")
    zip_bytes = read_regular(destination, MAX_ARCHIVE)
    observation = {"schema": "policy-impact-kit-assembly/v2" if bounds else "policy-impact-kit-assembly/v1", "status": "assembled", "target": args.target,
                   "source_commit": args.source_ref, "source_tree": tree, "archive": row(filename, zip_bytes, 0o644),
                   "manifest_sha256": sha(payload["manifest.json"]), "binary_before": row("policy-impact", before, 0o755),
                   "binary_after": row("policy-impact", after, 0o755), "binary_unchanged": True,
                   "product_calls": 0, "builds": 0, "network_calls": 0, "copied_source_files": len(source)}
    if bounds:
        observation["profile"] = "artifact-bounds/v1"
        observation["binary_source_bindings"] = manifest["binary_source_bindings"]
    with (out / "package-manifest.json").open("xb") as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(text_json(observation))
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"schema": observation["schema"], "status": "assembled", "archive": filename,
                      "archive_sha256": sha(zip_bytes), "product_calls": 0}, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--buildinfo", required=True)
    parser.add_argument("--target", choices=("darwin/arm64", "linux/amd64"), required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--profile", choices=("equality", "bounds"), default="equality")
    args = parser.parse_args()
    try:
        assemble(args)
    except (Invalid, OSError, UnicodeError, ValueError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, Invalid) else "ASSEMBLY_FAILED"
        print(json.dumps({"schema": "policy-impact-kit-assembly/v2" if args.profile == "bounds" else "policy-impact-kit-assembly/v1", "status": "error", "code": code,
                          "product_calls": 0}, separators=(",", ":")))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
