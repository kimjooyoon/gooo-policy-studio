#!/usr/bin/env python3
"""Inspect the new copy-only kit; optionally run only its four-call demo once.

No compiler/build/download/old checker or native corpus is invoked. Static
failure checks exercise only this ZIP/metadata verifier. Optional process
expectations are literals frozen before first execution by a separate reviewer.
"""
import argparse
import base64
import hashlib
import io
import importlib.util
import json
import os
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import warnings
import zipfile
from pathlib import Path

MAX_ARCHIVE = 256 << 20
MAX_SOURCE = 128 << 20
MAX_FILE = 16 << 20
MAX_REPORT = 64 << 20
MAX_MEMBERS = 4096
KIT_ROOT = "policy-impact-kit/"
MODULE = "github.com/kimjooyoon/gooo-policy-studio"
SEEDS = ("case.json", "artifact.json", "policy-internal.json", "policy-external.json")
EXPECTED_SEED_SHA = {
    "case.json": "5be75949203d42f89612a799072d60d8f63b080077a53e560cac1e60556a48a9",
    "artifact.json": "462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533",
    "policy-internal.json": "29f0deedd143e8d7ce82a67c5b1d860a579b10d6d0d96aef5e7e71ce4fa987b7",
    "policy-external.json": "9f5aed124ea80b67d905b4a00c6cadcc3c7b9e4006ba3c977a326290ef8a415f",
}
LITERAL_ORACLE_SHA256 = "996db2914a51d81bee76c326066a4e94bd0d24b9573944e0251e18a56ddb9d0d"
# LITERALS is inserted below from the independently hand-declared, pre-run
# finite public-example contract, never from observed product output.
LITERALS = json.loads(r'''{"workflow_literals":[{"id":"internal_to_external","before_seed":"policy-internal.json","after_seed":"policy-external.json","compare_exit":0,"compare_summary":{"schema":"policy-studio/artifact-impact-summary/v1","status":"compared","code":"COMPARISON_SAVED","simulation":true,"report_saved":true,"direction":"newly_denied","before":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false},"replay_exit":0,"replay_summary_by_platform":{"darwin/arm64":{"schema":"policy-studio/artifact-impact-replay-summary/v1","status":"verified","code":"HISTORICAL_COMPARISON_MATCH","historical":true,"simulation":true,"read_only":true,"authenticated_server_state":false,"committed":false,"target_effects_executed":false,"current_artifact_reads":0,"direction":"newly_denied","before":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false,"verifier_sha256":"sha256:741713fb0be66a6233e069ac42c04ca16954768068015ca4903603d71e471162"},"linux/amd64":{"schema":"policy-studio/artifact-impact-replay-summary/v1","status":"verified","code":"HISTORICAL_COMPARISON_MATCH","historical":true,"simulation":true,"read_only":true,"authenticated_server_state":false,"committed":false,"target_effects_executed":false,"current_artifact_reads":0,"direction":"newly_denied","before":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false,"verifier_sha256":"sha256:ed3763e0bc54af42e75b502f99b7e4a2e4db89800fc49794159238f787e2fe92"}}},{"id":"external_to_internal","before_seed":"policy-external.json","after_seed":"policy-internal.json","compare_exit":0,"compare_summary":{"schema":"policy-studio/artifact-impact-summary/v1","status":"compared","code":"COMPARISON_SAVED","simulation":true,"report_saved":true,"direction":"newly_allowed","before":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false},"replay_exit":0,"replay_summary_by_platform":{"darwin/arm64":{"schema":"policy-studio/artifact-impact-replay-summary/v1","status":"verified","code":"HISTORICAL_COMPARISON_MATCH","historical":true,"simulation":true,"read_only":true,"authenticated_server_state":false,"committed":false,"target_effects_executed":false,"current_artifact_reads":0,"direction":"newly_allowed","before":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false,"verifier_sha256":"sha256:741713fb0be66a6233e069ac42c04ca16954768068015ca4903603d71e471162"},"linux/amd64":{"schema":"policy-studio/artifact-impact-replay-summary/v1","status":"verified","code":"HISTORICAL_COMPARISON_MATCH","historical":true,"simulation":true,"read_only":true,"authenticated_server_state":false,"committed":false,"target_effects_executed":false,"current_artifact_reads":0,"direction":"newly_allowed","before":{"would_admit":false,"reason":"EVIDENCE_REJECTED","counts":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0}},"after":{"would_admit":true,"reason":"ADMITTED","counts":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0}},"added_claims":0,"removed_claims":0,"changed_claims":1,"claim_order_changed":false,"recipe_configuration_changed":true,"approval_budget_changed":false,"approval_checks_changed":false,"verifier_sha256":"sha256:ed3763e0bc54af42e75b502f99b7e4a2e4db89800fc49794159238f787e2fe92"}}}],"permission":{"eligible":true,"reason":"PROPOSED_PERMISSION_ELIGIBLE","modeled_http_status":200},"common_base_policy_result":{"before":{"approved":true,"reason":"APPROVED","amount_ok":true,"team_ok":true,"reviewer_ok":true,"self_ok":true,"submitted_ok":true},"after":{"approved":true,"reason":"APPROVED","amount_ok":true,"team_ok":true,"reviewer_ok":true,"self_ok":true,"submitted_ok":true},"change":{"changed":false,"direction":"UNCHANGED","reason_changed":false}},"both_direction_delta_detail":{"added":[],"removed":[],"changed":[{"claim_id":"destination_equal","predicate_changed":true,"artifact_schema_changed":false,"field_type_changed":false,"status_changed":true,"reason_changed":true,"actual_changed":false,"evidence_decision_changed":true}],"policy_identity_changed":true,"recipe_configuration_changed":true,"claim_order_changed":false,"approval_budget_changed":false,"approval_checks_changed":false,"control_plane_checks_changed":false},"both_sides_proposed_effect_decision":{"admissible":true,"reason":"WITHIN_EFFECT_BUDGET","target_ok":true,"session_ok":true,"filesystem_ok":true,"process_ok":true,"network_ok":true,"ui_ok":true,"discard_ok":true,"foreign_code_ok":true,"device_ok":true,"idempotency_ok":true},"actual_report_audit":{"schema":"policy-studio/artifact-impact-audit/v1","artifact_read_attempts":1,"acquisition_status":"read_success","input_files_read":3,"private_report_reserved":true,"private_report_write_planned":true,"effects":{"mutatesTarget":false,"mutatesSession":false,"writesFilesystem":true,"launchesProcess":false,"accessesNetwork":false,"changesUiState":false,"mayDiscardData":false,"executesForeignCode":false,"mutatesDevice":false,"idempotent":false}},"policy_detail_literals":{"internal":{"producer":{"acquisition_status":"read_success","artifact_reason":"ARTIFACT_VERIFIED","digest_ok":true,"schema_ok":true,"types_ok":true,"byte_count":157,"observed_size":157,"actual_sha256":"sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533","expected_sha256":"sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533"},"ordered_observations":[{"claim_id":"action_equal","verifier":"field_equals/v1","field":"action","expected":"prepare_export","actual":"prepare_export","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"destination_equal","verifier":"field_equals/v1","field":"destination","expected":"internal","actual":"internal","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"row_limit_equal","verifier":"field_equals/v1","field":"row_limit","expected":"500","actual":"500","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"dry_run_equal","verifier":"field_equals/v1","field":"dry_run","expected":"true","actual":"true","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"format_equal","verifier":"field_equals/v1","field":"format","expected":"jsonl","actual":"jsonl","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}}],"completion_summary":{"total":5,"pass":5,"fail":0,"unsupported":0,"truncated":0,"unknown":0,"valid":true,"complete":true,"reason":"ALL_PASS"},"admission_facts":{"provenance_ok":true,"base_policy_approved":true,"required_count":5,"observed_count":5,"admissible_evidence_count":5,"completion_ready":true,"approval_effect_admissible":true,"control_plane_effect_admissible":true},"native_final_decision":{"admitted":true,"reason":"ADMITTED","counts_ok":true,"provenance_ok":true,"base_policy_ok":true,"evidence_ok":true,"completion_ok":true,"approval_effect_ok":true,"control_plane_effect_ok":true}},"external":{"producer":{"acquisition_status":"read_success","artifact_reason":"ARTIFACT_VERIFIED","digest_ok":true,"schema_ok":true,"types_ok":true,"byte_count":157,"observed_size":157,"actual_sha256":"sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533","expected_sha256":"sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533"},"ordered_observations":[{"claim_id":"action_equal","verifier":"field_equals/v1","field":"action","expected":"prepare_export","actual":"prepare_export","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"destination_equal","verifier":"field_equals/v1","field":"destination","expected":"external","actual":"internal","status":"fail","reason":"FIELD_MISMATCH","native_evidence_decision":{"admissible":false,"reason":"EVIDENCE_INCOMPLETE","provider_ok":true,"evidence_ok":false,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"row_limit_equal","verifier":"field_equals/v1","field":"row_limit","expected":"500","actual":"500","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"dry_run_equal","verifier":"field_equals/v1","field":"dry_run","expected":"true","actual":"true","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}},{"claim_id":"format_equal","verifier":"field_equals/v1","field":"format","expected":"jsonl","actual":"jsonl","status":"pass","reason":"FIELD_EQUALS","native_evidence_decision":{"admissible":true,"reason":"ADMISSIBLE","provider_ok":true,"evidence_ok":true,"authority_ok":true,"binding_ok":true,"artifact_ok":true,"policy_ok":true,"freshness_ok":true,"deadline_ok":true}}],"completion_summary":{"total":5,"pass":4,"fail":1,"unsupported":0,"truncated":0,"unknown":0,"valid":true,"complete":false,"reason":"NON_PASS_RESULTS"},"admission_facts":{"provenance_ok":true,"base_policy_approved":true,"required_count":5,"observed_count":5,"admissible_evidence_count":4,"completion_ready":false,"approval_effect_admissible":true,"control_plane_effect_admissible":true},"native_final_decision":{"admitted":false,"reason":"EVIDENCE_REJECTED","counts_ok":true,"provenance_ok":true,"base_policy_ok":true,"evidence_ok":false,"completion_ok":false,"approval_effect_ok":true,"control_plane_effect_ok":true}}}}''')


class Rejected(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Rejected(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


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
            require(key not in result, "JSON_DUPLICATE")
            result[key] = value
        return result
    def nonfinite(_):
        raise Rejected("JSON_NONFINITE")
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=nonfinite)
    def walk(v):
        if isinstance(v, str):
            require(not any(0xD800 <= ord(c) <= 0xDFFF for c in v), "JSON_SURROGATE")
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(k); walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(value)
    return value


def safe_name(name):
    return (isinstance(name, str) and bool(re.fullmatch(r"[A-Za-z0-9._/-]+", name))
            and not name.startswith("/") and all(c not in ("", ".", "..") for c in name.split("/")))


def read_file(path, limit, mode=None):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "INPUT_FILE_INVALID")
    if mode is not None:
        require(stat.S_IMODE(before.st_mode) == mode, "INPUT_FILE_MODE")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and os.path.samestat(before, opened), "INPUT_FILE_CHANGED")
        chunks, size = [], 0
        while size <= limit:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
        sig = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(size <= limit and sig(before) == sig(opened) == sig(os.fstat(fd)) == sig(path.lstat()), "INPUT_FILE_CHANGED")
        return b"".join(chunks)
    finally:
        os.close(fd)


def local_git(repo, *args, cap=MAX_SOURCE):
    process = subprocess.Popen(["git", "-C", str(repo), *args], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    chunks, size = [], 0
    try:
        while selector.get_map():
            require(bool(selector.select(timeout=30)), "GIT_READ_TIMEOUT")
            block = os.read(process.stdout.fileno(), min(65536, cap + 1 - size))
            if not block:
                selector.unregister(process.stdout); break
            chunks.append(block); size += len(block)
            require(size <= cap, "GIT_READ_BOUNDS")
        require(process.wait(timeout=30) == 0, "GIT_READ_FAILED")
        return b"".join(chunks)
    finally:
        selector.close(); process.stdout.close()
        if process.poll() is None:
            process.kill(); process.wait()


def committed_source(repo, ref):
    require(bool(re.fullmatch(r"[0-9a-f]{40}", ref)), "SOURCE_REF_INVALID")
    require(local_git(repo, "rev-parse", "HEAD", cap=128).decode().strip() == ref, "SOURCE_REF_NOT_HEAD")
    require(not local_git(repo, "diff", "--name-only", "HEAD", "--", cap=1 << 20), "SOURCE_TRACKED_DIRTY")
    tree = local_git(repo, "rev-parse", ref + "^{tree}", cap=128).decode().strip()
    result, modes, size = {}, {}, 0
    raw = local_git(repo, "archive", "--format=tar", ref)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        for item in stream:
            name = item.name.rstrip("/")
            require(safe_name(name), "SOURCE_PATH_INVALID")
            if item.isdir():
                continue
            require(item.isfile() and name not in result and item.size <= MAX_FILE, "SOURCE_MEMBER_INVALID")
            require(not any(p in (".git", ".tools", "node_modules", "toolchain", "output", "bin", "out", "dist") for p in name.split("/")), "SOURCE_NONPUBLIC_PATH")
            f = stream.extractfile(item)
            require(f is not None, "SOURCE_MEMBER_INVALID")
            data = f.read(MAX_FILE + 1)
            size += len(data)
            require(len(data) == item.size and size <= MAX_SOURCE and len(result) < MAX_MEMBERS, "SOURCE_BOUNDS")
            result[name], modes[name] = data, 0o755 if item.mode & 0o111 else 0o644
    return tree, result, modes


def zip_members(raw):
    require(len(raw) <= MAX_ARCHIVE, "ZIP_BOUNDS")
    members, modes, total = {}, {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= MAX_MEMBERS, "ZIP_COUNT")
        require([x.filename for x in entries] == sorted(x.filename for x in entries), "ZIP_ORDER")
        for info in entries:
            require(info.filename.startswith(KIT_ROOT), "ZIP_ROOT")
            name = info.filename[len(KIT_ROOT):]
            require(safe_name(name) and name not in members, "ZIP_PATH_OR_DUPLICATE")
            mode = info.external_attr >> 16
            require(info.create_system == 3 and stat.S_ISREG(mode) and stat.S_IMODE(mode) in (0o644, 0o755), "ZIP_MODE")
            require(info.date_time == (1980, 1, 1, 0, 0, 0) and info.compress_type == zipfile.ZIP_DEFLATED
                    and info.flag_bits == 0 and not info.extra and not info.comment, "ZIP_NOT_CANONICAL")
            cap = 64 << 20 if name == "bin/policy-impact" else MAX_FILE
            require(info.file_size <= cap and info.compress_size <= MAX_ARCHIVE, "ZIP_MEMBER_BOUNDS")
            total += info.file_size
            require(total <= MAX_ARCHIVE, "ZIP_TOTAL_BOUNDS")
            data = archive.read(info)
            require(len(data) == info.file_size, "ZIP_MEMBER_SIZE")
            members[name], modes[name] = data, stat.S_IMODE(mode)
        require(not archive.comment, "ZIP_COMMENT")
    return members, modes


def build_record(binary, supplied, target):
    # Independent parsing of the supported Go1.27.3 inline buildinfo format.
    if target == "darwin/arm64":
        require(len(binary) >= 32 and binary[:4] == b"\xcf\xfa\xed\xfe" and
                struct.unpack_from("<II", binary, 4)[0] == 0x0100000C and struct.unpack_from("<I", binary, 12)[0] == 2, "BINARY_TARGET")
    elif target == "linux/amd64":
        require(len(binary) >= 64 and binary[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", binary, 18)[0] == 62
                and struct.unpack_from("<H", binary, 16)[0] in (2, 3), "BINARY_TARGET")
    else:
        raise Rejected("TARGET_UNSUPPORTED")
    def string_at(pos):
        n, shift = 0, 0
        for _ in range(10):
            require(pos < len(binary), "BINARY_BUILDINFO")
            b = binary[pos]; pos += 1; n |= (b & 127) << shift
            if b < 128:
                require(n <= 1 << 20 and pos + n <= len(binary), "BINARY_BUILDINFO")
                return binary[pos:pos + n], pos + n
            shift += 7
        raise Rejected("BINARY_BUILDINFO")
    def rows(version, body):
        out = {"go_version": version, "path": "", "module": "", "module_version": "", "settings": {}}
        seen = set()
        for line in body.splitlines():
            p = line.split("\t")
            if p[0] == "path":
                require(len(p) == 2 and "path" not in seen, "BINARY_BUILDINFO")
                out["path"] = p[1]; seen.add("path")
            elif p[0] == "mod":
                require(len(p) in (3, 4) and (len(p) == 3 or p[3] == "") and "mod" not in seen, "BINARY_BUILDINFO")
                out["module"], out["module_version"] = p[1:3]; seen.add("mod")
            elif p[0] == "build":
                require(len(p) == 2 and "=" in p[1], "BINARY_BUILDINFO")
                key, value = p[1].split("=", 1)
                require(key and key not in out["settings"], "BINARY_BUILDINFO")
                out["settings"][key] = value
            else:
                raise Rejected("BINARY_BUILDINFO_ROW")
        settings = out["settings"]
        require(version == "go1.27.3" and out["path"] == MODULE + "/cmd/policy-impact" and out["module"] == MODULE,
                "BINARY_PROGRAM_OR_GO")
        require(settings.get("GOOS", "") + "/" + settings.get("GOARCH", "") == target
                and settings.get("CGO_ENABLED") in ("0", "1") and settings.get("-trimpath") == "true"
                and settings.get("vcs") == "git" and re.fullmatch(r"[0-9a-f]{40}", settings.get("vcs.revision", ""))
                and settings.get("vcs.modified") in ("false", "true") and settings.get("-buildmode") == "exe"
                and settings.get("-compiler") == "gc", "BINARY_SETTINGS")
        return out
    matches = []
    start = binary.find(b"\xff Go buildinf:")
    while start >= 0:
        if start % 16 == 0 and binary[start + 14:start + 16] == b"\x08\x02":
            try:
                version, end = string_at(start + 32)
                mod, _ = string_at(end)
                require(len(mod) >= 33 and mod[-17] == 10 and mod[:16].hex() == "3077af0c9274080241e1c107e6d618e6"
                        and mod[-16:].hex() == "f932433186182072008242104116d8f2", "BINARY_BUILDINFO_FRAME")
                matches.append(rows(version.decode(), mod[16:-16].decode()))
            except (Rejected, UnicodeError):
                pass
        start = binary.find(b"\xff Go buildinf:", start + 1)
    require(len(matches) == 1, "BINARY_BUILDINFO_UNIQUE")
    lines = supplied.decode().splitlines()
    require(lines and lines[0] == "policy-impact: go1.27.3" and all(x.startswith("\t") for x in lines[1:]), "BUILDINFO_TEXT")
    require(exact(matches[0], rows("go1.27.3", "\n".join(x[1:] for x in lines[1:]))), "BUILDINFO_TEXT_MISMATCH")
    return matches[0]


def verify_members(members, modes, ref, tree, source, source_modes):
    required = {"bin/policy-impact", "try-demo.sh", "target.txt", "buildinfo.txt", "manifest.json", "SHA256SUMS", "notices/NOTICE.md"}
    copies = {"try-demo.sh": "examples/artifact-impact/try-demo.sh", "notices/LICENSE": "LICENSE",
              "notices/Go-LICENSE": "licenses/Go-LICENSE", "notices/LICENSE-REA": "internal/machinerules/assets/LICENSE-REA"}
    copies.update({"seeds/" + n: "examples/artifact-impact/" + n for n in SEEDS})
    copies.update({"docs/" + n: "docs/" + n for n in ("policy-impact-first-use.md", "artifact-policy-impact.md", "artifact-policy-replay.md")})
    required.update(copies)
    required.update("source/" + n for n in source)
    require(set(members) == required and set(modes) == required, "ZIP_ROSTER")
    expected_modes = {n: 0o644 for n in required}
    expected_modes.update({"bin/policy-impact": 0o755, "try-demo.sh": 0o755})
    expected_modes.update({"source/" + n: m for n, m in source_modes.items()})
    require(modes == expected_modes, "ZIP_EXACT_MODES")
    for name, original in copies.items():
        require(members[name] == source[original], "COPIED_SOURCE_MISMATCH")
    for name, data in source.items():
        require(members["source/" + name] == data, "SOURCE_SNAPSHOT_MISMATCH")
    for name in SEEDS:
        require(digest(members["seeds/" + name]) == EXPECTED_SEED_SHA[name], "SYNTHETIC_SEED_CHANGED")
    text = members["SHA256SUMS"].decode("ascii")
    expected_text = "".join(digest(members[n]) + "  " + n + "\n" for n in sorted(members) if n != "SHA256SUMS")
    require(text == expected_text, "CHECKSUM_ROSTER_OR_BYTES")
    target = members["target.txt"].decode("ascii")
    require(target in ("darwin/arm64\n", "linux/amd64\n"), "TARGET_TEXT")
    target = target.strip()
    actual = build_record(members["bin/policy-impact"], members["buildinfo.txt"], target)
    manifest = strict_json(members["manifest.json"])
    require(type(manifest) is dict and set(manifest) == {"schema", "target", "source", "binary", "payload", "assembly", "scope", "limitations"}, "MANIFEST_FIELDS")
    row = lambda n, raw, m: {"path": n, "mode": format(m, "04o"), "bytes": len(raw), "sha256": digest(raw)}
    require(manifest["schema"] == "policy-impact-kit/v1" and manifest["target"] == target, "MANIFEST_SCHEMA_TARGET")
    require(exact(manifest["source"], {"commit": ref, "tree": tree, "tracked_files": [row(n, source[n], source_modes[n]) for n in sorted(source)]}), "MANIFEST_SOURCE")
    require(exact(manifest["binary"], {"bytes": len(members["bin/policy-impact"]), "sha256": digest(members["bin/policy-impact"]), "build": actual}), "MANIFEST_BINARY")
    require(exact(manifest["payload"], [row(n, members[n], modes[n]) for n in sorted(members) if n not in ("manifest.json", "SHA256SUMS")]), "MANIFEST_PAYLOAD")
    require(exact(manifest["assembly"], {"copy_only": True, "product_calls": 0, "builds": 0, "network_calls": 0,
                 "build_revision_is_package_source_commit": actual["settings"]["vcs.revision"] == ref,
                 "binary_source_linkage": "Package snapshot and embedded source identities must be reviewed independently; VCS metadata is preserved, not rewritten."}), "MANIFEST_ASSEMBLY")
    require(exact(manifest["limitations"], {"macos_developer_id_or_notarization_claimed": False, "download_quarantine_tested": False,
                 "minimum_macos_runtime_verified": False, "portable_historical_replay": False, "binary_was_rebuilt_during_assembly": False}), "MANIFEST_LIMITS")
    require(manifest["scope"] == "Experimental finite local simulation and unsigned same-implementation historical replay; no current execution grant or publisher authentication.", "MANIFEST_SCOPE")
    notice = members["notices/NOTICE.md"].decode("utf-8")
    require(all(x in notice for x in ("Google does not endorse", "dirty", "notarization", "quarantine", "issuer", "MIT", "BSD")), "NOTICE_LIMITS")
    return manifest


def failure_checks(members, modes, ref, tree, source, source_modes):
    cases = [
        ("changed_binary", "bin/policy-impact", members["bin/policy-impact"] + b"changed"),
        ("changed_seed", "seeds/artifact.json", b"{}\n"),
        ("changed_demo", "try-demo.sh", b"#!/bin/sh\nexit 0\n"),
        ("changed_metadata", "buildinfo.txt", members["buildinfo.txt"].replace(b"go1.27.3", b"go1.27.2")),
        ("changed_target", "target.txt", b"linux/arm64\n"),
        ("changed_source", "source/go.mod", b"module invalid\n"),
        ("unknown_member", "extra.json", b"{}"),
    ]
    observations = []
    for label, name, value in cases:
        changed = dict(members); changed[name] = value
        changed_modes = dict(modes); changed_modes.setdefault(name, 0o644)
        try:
            verify_members(changed, changed_modes, ref, tree, source, source_modes)
        except Rejected as error:
            observations.append({"case": label, "rejected": True, "code": str(error), "product_calls": 0})
        else:
            raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    for label, name, mode in (("binary_not_executable", "bin/policy-impact", 0o644), ("seed_executable", "seeds/case.json", 0o755)):
        changed = dict(modes); changed[name] = mode
        try:
            verify_members(members, changed, ref, tree, source, source_modes)
        except Rejected as error:
            observations.append({"case": label, "rejected": True, "code": str(error), "product_calls": 0})
        else:
            raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    def synthetic(entries):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)  # Intentional duplicate fixture only.
            with zipfile.ZipFile(stream, "w") as archive:
                for name, mode in entries:
                    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.create_system = 3
                    info.external_attr = mode << 16; info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, b"x")
        return stream.getvalue()
    for label, entries in (
        ("zip_traversal", [(KIT_ROOT + "../escape", stat.S_IFREG | 0o644)]),
        ("zip_absolute", [("/absolute", stat.S_IFREG | 0o644)]),
        ("zip_symlink", [(KIT_ROOT + "link", stat.S_IFLNK | 0o777)]),
        ("zip_fifo", [(KIT_ROOT + "fifo", stat.S_IFIFO | 0o644)]),
        ("zip_duplicate", [(KIT_ROOT + "same", stat.S_IFREG | 0o644)] * 2),
    ):
        try:
            zip_members(synthetic(entries))
        except Rejected as error:
            observations.append({"case": label, "rejected": True, "code": str(error), "product_calls": 0})
        else:
            raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    oversized = bytearray(synthetic([(KIT_ROOT + "bin/policy-impact", stat.S_IFREG | 0o755)]))
    central = oversized.index(b"PK\x01\x02")
    struct.pack_into("<I", oversized, central + 24, (64 << 20) + 1)
    try:
        zip_members(bytes(oversized))
    except Rejected as error:
        observations.append({"case": "zip_declared_oversized", "rejected": True, "code": str(error), "product_calls": 0})
    else:
        raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    # JSON type identity and duplicate-key failures are separate from hashes.
    for label, raw in (("manifest_duplicate", b'{"schema":1,"schema":2}'), ("manifest_nonfinite", b'{"x":NaN}')):
        try:
            strict_json(raw)
        except Rejected as error:
            observations.append({"case": label, "rejected": True, "code": str(error), "product_calls": 0})
        else:
            raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    require(not exact({"n": True}, {"n": 1}), "TYPE_IDENTITY_CHECK_FAILED")
    original_binary = members["bin/policy-impact"]
    target = members["target.txt"].decode().strip()
    for label, changed in (("embedded_missing_GOOS", original_binary.replace(b"GOOS=", b"NOOS=")),
                           ("embedded_missing_GOARCH", original_binary.replace(b"GOARCH=", b"NOARCH="))):
        try:
            build_record(changed, members["buildinfo.txt"], target)
        except Rejected as error:
            observations.append({"case": label, "rejected": True, "code": str(error), "product_calls": 0})
        else:
            raise Rejected("FAILURE_CHECK_ACCEPTED_INVALID")
    return observations


def canonical(value):
    # The finite fixture uses only integral JSON numbers. Match Go's default
    # compact UTF-8/HTML escaping; struct field order is supplied by typed rows.
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    for a, b in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(a, b)
    return text.encode()


def hash_value(v):
    return "sha256:" + digest(canonical(v))


def identity_for(source, target):
    h = lambda p: "sha256:" + digest(source[p])
    json_input = hash_value({"domain": "policy-studio/strict-json-source/v1", "files": {n: digest(source["internal/jsoninput/" + n]) for n in ("provenance.go", "strict.go")}})
    names = ("model.go", "compare.go", "validate.go", "delta.go", "identity.go", "files.go", "files_unix.go", "files_other.go")
    host = [{"path": n, "sha256": h("internal/artifactimpact/" + n)} for n in names]
    producer = {"schema": "policy-studio/artifact-producer-source/v2", "producer_id": "flat-json/v2", "verifier_id": "artifact-verifier-registry/v2"}
    for field, n in (("model_sha256", "model"), ("validation_sha256", "validation"), ("verifier_sha256", "verifier"), ("reader_sha256", "reader"), ("reader_unix_sha256", "reader_unix"), ("reader_other_sha256", "reader_other"), ("identity_sha256", "identity")):
        producer[field] = h("internal/artifactpreflight/" + n + ".go")
    producer["json_input_sha256"] = json_input
    spec = importlib.util.spec_from_file_location("artifact_numeric_source", Path(__file__).with_name("artifact_numeric_source.py"))
    numeric_source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(numeric_source)
    producer["numeric_bindings"] = numeric_source.expected_numeric_bindings(source, json_input)
    base_generation = strict_json(source["internal/policy/generation.json"])
    base = {"source_sha256": h("internal/policy/approval.gooo"), "generated_sha256": h("internal/policy/generated.txt"),
            "compiler_source_sha": base_generation["compiler"]["compiler_source_sha"], "generation_sha256": h("internal/policy/generation.json"), "adapter_sha256": h("internal/policy/bridge_generated.go")}
    cp = "internal/completion/"
    completion = {"policy_sha256": hash_value({"schema": "policy-studio/completion-policy/v1", "policy_id": "impact-source-probe", "revision": 1, "required_claims": ["source"]}), "source_sha256": h(cp + "source.gooo"), "generated_sha256": h(cp + "generated.txt"), "bridge_sha256": h(cp + "bridge.txt"),
                  "generation_sha256": h(cp + "generation.json"), "compiler_source_sha": source[cp + "compiler-version.txt"].decode().strip()}
    mg = strict_json(source["internal/machinerules/generation.json"])
    paths = [("examples/evidence-admission/admission.gooo", "original-admission.gooo"), ("examples/evidence-admission/proof_authority.gooo", "original-proof_authority.gooo"),
             ("examples/tool-effects/tool_effects.gooo", "original-tool_effects.gooo"), ("examples/tool-effects/effect_budget.gooo", "original-effect_budget.gooo"),
             ("cmd/generate-machine/main.go", "generator.go.txt"), ("internal/machinerules/rules.go", "host-transport.go.txt"), ("internal/machinerules/bindings.go", "host-bindings.go.txt")]
    paths.extend(("examples/artifact-gate/" + p, p.replace("/", "-")) for p in ("admission.gooo", "proof_authority.gooo", "tool_effects.gooo", "effect_budget.gooo", "machine.gooo", "LICENSE-REA", "compiler-version.txt", "evidence.workspace.json", "effects.workspace.json", "admission.workspace.json", "evidence.inputs.json", "effects.inputs.json", "receipts/evidence-workspace.json", "receipts/effects-workspace.json"))
    machine_sources = [{"path": p, "sha256": h("internal/machinerules/assets/" + a)} for p, a in paths]
    require(exact({r["path"]: r["sha256"] for r in machine_sources}, mg["sources"]), "MACHINE_SOURCE_GENERATION")
    projections = []
    for kind in ("evidence", "effects", "final"):
        g = mg["projections"][kind]
        require(all(h("internal/machinerules/" + kind + "/" + f) == g[k] for f, k in (("source.gooo", "source_sha256"), ("generated.txt", "generated_sha256"), ("bridge.txt", "bridge_sha256"))), "MACHINE_PROJECTION_GENERATION")
        projections.append({"name": kind, "source_sha256": g["source_sha256"], "generated_sha256": g["generated_sha256"], "bridge_sha256": g["bridge_sha256"], "workspace_receipt_sha256": g["workspace_receipt_sha256"]})
    machine = {"schema": "policy-studio/machine-provenance/v1", "compiler_source_sha": mg["compiler"]["compiler_source_sha"], "generation_sha256": h("internal/machinerules/generation.json"), "sources": machine_sources, "projections": projections}
    goos, goarch = target.split("/")
    identity = {"schema": "policy-studio/artifact-impact-source/v1", "host_sources": host, "host_sha256": hash_value(host), "json_input_sha256": json_input,
                "producer": producer, "base": base, "completion": completion, "machine_rules": machine, "go_version": "go1.27.3", "goos": goos, "goarch": goarch}
    replay = {"schema": "policy-studio/artifact-impact-replay-source/v1", "sources": [{"path": n, "sha256": h("internal/artifactimpact/" + n)} for n in ("replay.go", "replay_identity.go", "replay_files.go")], "comparison": identity, "verifier_sha256": ""}
    return identity, hash_value(replay)


def selected(mapping, keys):
    require(isinstance(mapping, dict) and all(k in mapping for k in keys), "REPORT_LITERAL_FIELD_MISSING")
    return {k: mapping[k] for k in keys}


def check_report(raw, direction, members, source, target, work):
    saved = strict_json(raw)
    require(type(saved) is dict and set(saved) == {"schema", "id", "simulation", "authenticated_server_state", "committed", "target_effects_executed", "observation_unix", "inputs", "implementation", "permission", "base_receipt", "before", "after", "delta", "audit", "scope"}, "REPORT_ROSTER")
    require(saved["schema"] == "policy-studio/artifact-policy-comparison/v1" and exact(selected(saved, ("simulation", "authenticated_server_state", "committed", "target_effects_executed")),
            {"simulation": True, "authenticated_server_state": False, "committed": False, "target_effects_executed": False}), "REPORT_SCOPE_FLAGS")
    require(type(saved["observation_unix"]) is int and 0 < saved["observation_unix"] < 4102444800, "REPORT_CLOCK")
    expected_id, expected_replay = identity_for(source, target)
    require(exact(saved["implementation"], expected_id), "REPORT_SOURCE_IDENTITY")
    require(exact(saved["permission"], LITERALS["permission"]) and exact(saved["base_receipt"]["result"], LITERALS["common_base_policy_result"]), "REPORT_BASE_PERMISSION")
    require(exact(saved["audit"], LITERALS["actual_report_audit"]), "REPORT_AUDIT")
    delta = dict(LITERALS["both_direction_delta_detail"]); delta["direction"] = direction
    require(exact(saved["delta"], delta), "REPORT_DELTA")
    original_case = members["seeds/case.json"].replace(b"/replace-with-your-private-directory/artifact.json", (str(work) + "/artifact.json").encode())
    case = strict_json(original_case)
    seeds = ("policy-internal.json", "policy-external.json") if direction == "newly_denied" else ("policy-external.json", "policy-internal.json")
    input_raw = (original_case, members["seeds/" + seeds[0]], members["seeds/" + seeds[1]])
    inputs = {k: {"raw_sha256": "sha256:" + digest(b), "semantic_sha256": hash_value(strict_json(b))} for k, b in zip(("case", "before", "after"), input_raw)}
    require(exact(saved["inputs"], inputs), "REPORT_INPUT_BINDINGS")
    base = saved["base_receipt"]
    expected_base_input = {"request": case["request"], "reviewer": {"key": case["principal"]["key"], "team": case["principal"]["team"], "active": case["principal"]["active"]}, "before": case["base_rules"], "after": case["base_rules"]}
    require(exact(base["input"], expected_base_input), "REPORT_BASE_INPUT")
    for side_name, seed in zip(("before", "after"), seeds):
        side = saved[side_name]
        policy = strict_json(members["seeds/" + seed])
        kind = "internal" if seed == "policy-internal.json" else "external"
        literal = LITERALS["policy_detail_literals"][kind]
        context = {"domain": "policy-studio/artifact-impact-simulation-context/v1", "side": side_name, "case": case, "inputs": inputs, "policy": policy, "implementation": expected_id}
        require(exact(side["context"], context) and side["context_sha256"] == hash_value(context), "REPORT_CONTEXT_BINDING")
        version = hash_value({"domain": "policy-studio/artifact-impact-simulation-policy/v1", "policy": policy, "case": case, "implementation": expected_id})
        require(side["simulation_policy_version"] == version, "REPORT_POLICY_VERSION")
        producer = side["producer"]
        require(exact(selected(producer, literal["producer"]), literal["producer"]), "REPORT_PRODUCER_LITERALS")
        require(base64.b64decode(producer["artifact_base64"], validate=True) == members["seeds/artifact.json"] and producer["context_digest"] == side["context_sha256"]
                and producer["observation_unix"] == saved["observation_unix"] and exact(producer["identity"], expected_id["producer"]), "REPORT_PRODUCER_BINDINGS")
        observations = producer["observations"]
        require(len(observations) == len(side["evidence"]) == 5, "REPORT_CLAIM_COUNT")
        for observation, evidence, expected in zip(observations, side["evidence"], literal["ordered_observations"]):
            observation_expected = {k: v for k, v in expected.items() if k != "native_evidence_decision"}
            require(exact(selected(observation, observation_expected), observation_expected), "REPORT_ORDERED_CLAIM")
            require(evidence["claim_id"] == expected["claim_id"] and exact(evidence["decision"], expected["native_evidence_decision"]), "REPORT_NATIVE_EVIDENCE")
        completed = side["completion"]
        require(exact(completed["summary"], literal["completion_summary"]), "REPORT_COMPLETION_LITERALS")
        for name, budget in (("proposed_approval", "approval_budget"), ("proposed_control_plane", "control_plane_budget")):
            require(exact(side[name]["decision"], LITERALS["both_sides_proposed_effect_decision"]) and exact(side[name]["budget"], policy[budget]), "REPORT_EFFECT_LITERALS")
        require(exact(side["admission_facts"], literal["admission_facts"]) and exact(side["decision"], literal["native_final_decision"]), "REPORT_NATIVE_FINAL")
        require(exact(side["would_admit"], kind == "internal") and side["reason"] == ("ADMITTED" if kind == "internal" else "EVIDENCE_REJECTED"), "REPORT_SIDE_FINAL")
    return saved, expected_replay


def capture_demo(command, cwd, trace):
    """Bound both pipes and terminate this fresh process group on uncertainty."""
    process, selector = None, None
    raw = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + 45
    stopped = ""
    def kill(sig):
        if process is None:
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=cwd, start_new_session=True)
        trace.update({"spawned": True, "product_calls_known": False, "product_calls": None, "completed_product_calls": None})
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not stopped:
                    stopped = "timeout"; kill(signal.SIGTERM); deadline = time.monotonic() + 1
                    continue
                kill(signal.SIGKILL)
                break
            for key, _ in selector.select(timeout=min(remaining, 1)):
                block = os.read(key.fileobj.fileno(), 8193 - len(raw[key.data]))
                if not block:
                    selector.unregister(key.fileobj)
                else:
                    raw[key.data].extend(block)
                    if len(raw[key.data]) > 8192:
                        stopped = "output_bound"; kill(signal.SIGTERM); deadline = time.monotonic() + 1
                        selector.unregister(key.fileobj)
        if stopped:
            kill(signal.SIGKILL)  # Include descendants even if the shell exited.
        try:
            exit_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            stopped = stopped or "exit_timeout"; kill(signal.SIGKILL); exit_code = process.wait(timeout=1)
        return {"spawned": True, "reaped": True, "exit_code": exit_code, "termination_reason": stopped,
                "stdout": bytes(raw["stdout"]), "stderr": bytes(raw["stderr"]),
                "stdout_complete": len(raw["stdout"]) <= 8192 and not stopped,
                "stderr_complete": len(raw["stderr"]) <= 8192 and not stopped}
    finally:
        aborted = sys.exc_info()[0] is not None
        if selector is not None:
            selector.close()
        if process is not None:
            process.stdout.close(); process.stderr.close()
            if aborted or process.poll() is None:
                kill(signal.SIGKILL); process.wait(timeout=1)
        trace.update({"reaped": process is not None and process.poll() is not None, "process_exit": process.poll() if process is not None else None,
                      "termination_reason": stopped or ("interrupted_or_capture_failed" if aborted else ""),
                      "stdout_raw_base64": base64.b64encode(raw["stdout"]).decode(), "stderr_raw_base64": base64.b64encode(raw["stderr"]).decode()})


def run_demo(members, modes, source, target, trace):
    host = {("Darwin", "arm64"): "darwin/arm64", ("Linux", "x86_64"): "linux/amd64"}.get((platform.system(), platform.machine()))
    require(host == target, "DEMO_HOST_MISMATCH")
    extraction = Path(tempfile.mkdtemp(prefix="gooo-policy-impact-kit-verify-", dir="/tmp")).resolve()
    trace["extraction_directory"] = str(extraction)
    os.chmod(extraction, 0o700)
    root = extraction / "policy-impact-kit"; root.mkdir(mode=0o700)
    for name in sorted(members):
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as f:
            f.write(members[name]); os.fchmod(f.fileno(), modes[name])
    require(all(read_file(root / n, MAX_ARCHIVE) == b for n, b in members.items()), "EXTRACTION_BYTES")
    binary_before = read_file(root / "bin/policy-impact", 64 << 20, 0o755)
    started = int(time.time())
    trace["spawn_attempted"] = True
    captured = capture_demo([str(root / "try-demo.sh")], root, trace)
    trace.update({"spawned": captured["spawned"], "reaped": captured["reaped"], "process_exit": captured["exit_code"],
                  "termination_reason": captured["termination_reason"], "stdout_complete": captured["stdout_complete"], "stderr_complete": captured["stderr_complete"],
                  "stdout_raw_base64": base64.b64encode(captured["stdout"]).decode(), "stderr_raw_base64": base64.b64encode(captured["stderr"]).decode()})
    for name, raw in (("demo.stdout", captured["stdout"]), ("demo.stderr", captured["stderr"])):
        with (extraction / name).open("xb") as f:
            os.fchmod(f.fileno(), 0o600); f.write(raw)
    # Recover truthful partial lifecycle data before success assertions. A
    # timeout with no workspace line leaves counts explicitly unknown.
    try:
        partial = strict_json(captured["stdout"])
        partial_path = partial.get("work_directory", "") if isinstance(partial, dict) else ""
        if re.fullmatch(r"/(?:private/)?tmp/gooo-policy-impact\.[A-Za-z0-9]+", partial_path):
            trace["private_work_directory"] = partial_path
            partial_calls = read_file(Path(partial_path) / "product-calls.tsv", 8192, 0o600)
            trace["call_log_raw_base64"] = base64.b64encode(partial_calls).decode()
            lines = [line.split("\t") for line in partial_calls.decode().splitlines()]
            trace["product_calls"] = sum(len(r) == 5 and r[3] == "started" for r in lines)
            trace["completed_product_calls"] = sum(len(r) == 5 and r[3] == "completed" for r in lines)
            trace["product_calls_known"] = True
    except (Rejected, OSError, UnicodeError, ValueError):
        pass
    require(captured["stdout_complete"] and captured["stderr_complete"], "DEMO_PROCESS_UNCERTAIN")
    require(captured["exit_code"] == 0 and captured["stderr"] == b"", "DEMO_PROCESS_FAILED")
    result = strict_json(captured["stdout"])
    require(type(result) is dict and set(result) == {"schema", "status", "work_directory", "product_calls", "simulation"}
            and result["schema"] == "policy-impact-kit-demo/v1" and result["status"] == "completed" and exact(result["product_calls"], 4)
            and exact(result["simulation"], True), "DEMO_SUMMARY")
    work = Path(result["work_directory"])
    require(re.fullmatch(r"/(?:private/)?tmp/gooo-policy-impact\.[A-Za-z0-9]+", str(work)) and work.resolve() == work
            and stat.S_ISDIR(work.lstat().st_mode) and stat.S_IMODE(work.stat().st_mode) == 0o700, "DEMO_PRIVATE_DIRECTORY")
    expected_calls = "".join(str(i) + "\t" + action + "\t" + direction + "\t" + phase + "\t" + rc + "\n"
                             for i, action, direction in ((1, "compare", "newly_denied"), (2, "compare", "newly_allowed"), (3, "replay", "newly_denied"), (4, "replay", "newly_allowed"))
                             for phase, rc in (("started", "-"), ("completed", "0")))
    calls = read_file(work / "product-calls.tsv", 8192, 0o600)
    trace.update({"call_log_raw_base64": base64.b64encode(calls).decode(), "private_work_directory": str(work)})
    require(calls.decode() == expected_calls, "DEMO_CALL_LOG")
    deleted = read_file(work / "inputs.deleted", 8192, 0o600)
    trace["deleted_inputs_raw_base64"] = base64.b64encode(deleted).decode()
    require(deleted == ("\n".join(SEEDS) + "\n").encode() and all(not (work / n).exists() and not (work / n).is_symlink() for n in SEEDS), "DEMO_INPUT_REMOVAL")
    rows = read_file(work / "digests.tsv", 8192, 0o600).decode().splitlines()
    digests = {}
    for row in rows:
        pair = row.split("\t")
        require(len(pair) == 2 and pair[0] not in digests and bool(re.fullmatch(r"[0-9a-f]{64}", pair[1])), "DEMO_DIGEST_LOG")
        digests[pair[0]] = pair[1]
    observations = []
    trace["observations"] = observations
    for i, workflow in enumerate(LITERALS["workflow_literals"]):
        short = "denied" if i == 0 else "allowed"
        direction = "newly_denied" if i == 0 else "newly_allowed"
        compare_name = ("01" if i == 0 else "02") + "-compare-" + short
        replay_name = ("03" if i == 0 else "04") + "-replay-" + short
        compare_raw = read_file(work / (compare_name + ".summary.json"), 8192, 0o600)
        replay_raw = read_file(work / (replay_name + ".summary.json"), 8192, 0o600)
        report_raw = read_file(work / (compare_name + ".report.json"), MAX_REPORT, 0o600)
        observations.append({"direction": direction, "compare_summary_raw_base64": base64.b64encode(compare_raw).decode(), "replay_summary_raw_base64": base64.b64encode(replay_raw).decode(),
                             "report_raw_base64": base64.b64encode(report_raw).decode(), "report_bytes": len(report_raw), "report_sha256": digest(report_raw), "report_mode": "0600"})
        require(exact(strict_json(compare_raw), workflow["compare_summary"]), "DEMO_COMPARE_SUMMARY_LITERAL")
        saved, expected_verifier = check_report(report_raw, direction, members, source, target, work)
        expected_replay = dict(workflow["replay_summary_by_platform"][target])
        # Preserve every frozen semantic literal; only the separately derived
        # current source identity changes with this explicitly versioned unit.
        expected_replay["verifier_sha256"] = expected_verifier
        require(exact(strict_json(replay_raw), expected_replay), "DEMO_REPLAY_SUMMARY_LITERAL")
        require(started - 1 <= saved["observation_unix"] <= int(time.time()), "DEMO_OBSERVATION_BOUND")
        require(digests.get(short + "_report_before_replay") == digests.get(short + "_report_after_replay") == digest(report_raw), "DEMO_RETAINED_REPORT_UNCHANGED")
        require(digests.get(compare_name + ".summary") == digest(compare_raw) and digests.get(replay_name + ".summary") == digest(replay_raw), "DEMO_SUMMARY_DIGESTS")
        for n in (compare_name, replay_name):
            require(read_file(work / (n + ".stderr"), 8192, 0o600) == b"", "DEMO_PRODUCT_STDERR")
    binary_after = read_file(root / "bin/policy-impact", 64 << 20, 0o755)
    require(binary_before == binary_after and digests.get("binary_before") == digests.get("binary_after") == digest(binary_before), "DEMO_BINARY_UNCHANGED")
    require(all(read_file(root / n, MAX_ARCHIVE) == b for n, b in members.items()), "DEMO_KIT_UNCHANGED")
    copied_case = members["seeds/case.json"].replace(b"/replace-with-your-private-directory/artifact.json", (str(work) + "/artifact.json").encode())
    for n in SEEDS:
        require(digests.get("input_" + n) == digest(copied_case if n == "case.json" else members["seeds/" + n]), "DEMO_COPIED_INPUT_DIGEST")
    require(len(digests) == 14, "DEMO_DIGEST_ROSTER")
    trace.update({"status": "accepted", "product_calls": 4, "completed_product_calls": 4, "product_calls_known": True,
                  "compare_calls": 2, "replay_calls": 2, "digests": digests,
                  "scope": "Four-call synthetic distribution workflow; report checks cover explicit frozen literals and source/input bindings, not a general verifier or authenticated history."})
    return trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--run-demo", action="store_true")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise Rejected("VERIFICATION_INTERRUPTED")
    for number in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGHUP", signal.SIGTERM)):
        signal.signal(number, interrupted)
    output_fd = None
    result = None
    try:
        # Reserve before any optional product operation. Keep failures private.
        output_fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.fchmod(output_fd, 0o600)
        archive_bytes = read_file(args.archive, MAX_ARCHIVE)
        tree, source, source_modes = committed_source(Path(args.repo).resolve(), args.source_ref)
        members, modes = zip_members(archive_bytes)
        manifest = verify_members(members, modes, args.source_ref, tree, source, source_modes)
        failures = failure_checks(members, modes, args.source_ref, tree, source, source_modes)
        result = {"schema": "policy-impact-kit-verification/v1", "status": "accepted", "archive_bytes": len(archive_bytes), "archive_sha256": digest(archive_bytes),
                  "source_commit": args.source_ref, "source_tree": tree, "target": manifest["target"], "member_count": len(members),
                  "tracked_source_files": len(source), "manifest_sha256": digest(members["manifest.json"]), "binary": manifest["binary"],
                  "static_failure_checks": failures, "product_calls": 0, "builds": 0, "network_calls": 0,
                  "literal_oracle_sha256": LITERAL_ORACLE_SHA256, "oracle_method": "Independently hand-declared pre-run public-example literals; embedded source hashes reconstructed from committed source, never inferred from runtime answers."}
        if args.run_demo:
            result["demo"] = {"status": "pending", "spawn_attempted": False, "spawned": False,
                              "product_calls": 0, "completed_product_calls": 0, "product_calls_known": True}
            run_demo(members, modes, source, manifest["target"], result["demo"])
            result["product_calls"] = result["demo"]["product_calls"]
        else:
            result["demo"] = {"status": "not_run", "product_calls": 0}
        require(read_file(args.archive, MAX_ARCHIVE) == archive_bytes, "ARCHIVE_CHANGED_DURING_VERIFICATION")
        final_tree, final_source, final_modes = committed_source(Path(args.repo).resolve(), args.source_ref)
        require((tree, source, source_modes) == (final_tree, final_source, final_modes), "SOURCE_CHANGED_DURING_VERIFICATION")
        raw = (json.dumps(result, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
        require(len(raw) <= 128 << 20, "VERIFICATION_OUTPUT_BOUNDS")
        with os.fdopen(output_fd, "wb") as stream:
            output_fd = None; stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({"schema": result["schema"], "status": "accepted", "archive_sha256": result["archive_sha256"], "product_calls": result["product_calls"]}, separators=(",", ":")))
        return 0
    except (Rejected, OSError, UnicodeError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, Rejected) else "VERIFICATION_FAILED"
        if result is None:
            result = {"schema": "policy-impact-kit-verification/v1", "product_calls": 0, "builds": 0, "network_calls": 0}
        result.update({"status": "error", "code": code})
        if "demo" in result:
            result["demo"]["status"] = "error"
            result["product_calls"] = result["demo"].get("product_calls")
            result["product_execution_may_have_started"] = result["demo"].get("spawned", False)
        else:
            result["product_execution_may_have_started"] = False
        if output_fd is not None:
            try:
                with os.fdopen(output_fd, "wb") as stream:
                    output_fd = None; stream.write((json.dumps(result, sort_keys=True, indent=2) + "\n").encode()); stream.flush(); os.fsync(stream.fileno())
            finally:
                if output_fd is not None:
                    os.close(output_fd); output_fd = None
        print(json.dumps({"schema": result["schema"], "status": "error", "code": code,
                          "product_execution_may_have_started": result["product_execution_may_have_started"]}, separators=(",", ":")))
        return 2
    finally:
        if output_fd is not None:
            os.close(output_fd)


if __name__ == "__main__":
    sys.exit(main())
