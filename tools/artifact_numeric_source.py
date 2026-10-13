"""Derive current numeric provenance from tracked source bytes, never answers.

This small adapter lets existing equality CI observers check the explicitly
versioned new implementation. It does not execute a product, regenerate rules,
import a historical oracle or validate an issuer signature.
"""
import hashlib
import json


PIN = "83928fa4538245abe33b08549da47f8cbdc50ed2"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def unique(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate numeric source metadata")
        value[key] = item
    return value


def raw_member(raw, selected):
    # Match json.RawMessage: retain the exact nested token bytes, including
    # their interior whitespace, instead of normalizing observed identities.
    text = raw.decode("utf-8", "strict")
    decoder = json.JSONDecoder(object_pairs_hook=unique)
    cursor = text.index("{") + 1
    while True:
        while text[cursor].isspace(): cursor += 1
        if text[cursor] == "}": break
        key, cursor = decoder.raw_decode(text, cursor)
        while text[cursor].isspace(): cursor += 1
        if text[cursor] != ":": raise ValueError("numeric metadata field")
        cursor += 1
        while text[cursor].isspace(): cursor += 1
        start = cursor
        _, cursor = decoder.raw_decode(text, cursor)
        if key == selected: return text[start:cursor].encode("utf-8")
        while text[cursor].isspace(): cursor += 1
        if text[cursor] == "}": break
        if text[cursor] != ",": raise ValueError("numeric metadata separator")
        cursor += 1
    raise ValueError("numeric metadata member absent")


def expected_numeric_bindings(source, json_input):
    prefix = "internal/artifactnumeric/"
    raw = source[prefix + "generation.json"]
    record = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
    keys = {"schema", "source_sha256", "generated_sha256", "bridge_sha256",
            "model_sha256", "bindings_sha256", "generator_sha256", "compiler", "activity"}
    if set(record) != keys or record["schema"] != "policy-studio/artifact-int64-generation/v1":
        raise ValueError("numeric generation schema or roster")
    if source[prefix + "rules_generated.go"] != source[prefix + "generated.txt"] or source[prefix + "bridge.go"] != source[prefix + "bridge.txt"] or source[prefix + "generator.txt"] != source["cmd/generate-artifact-bounds/main.go"]:
        raise ValueError("numeric retained code differs from actual source")
    fields = {"source_sha256": "source.gooo", "generated_sha256": "rules_generated.go",
              "bridge_sha256": "bridge.go", "model_sha256": "model.go",
              "bindings_sha256": "bindings.go", "generator_sha256": "generator.txt"}
    expected = {"schema": "policy-studio/artifact-int64-native-bindings/v1"}
    for field, name in fields.items():
        expected[field] = digest(source[prefix + name])
        if record[field] != expected[field]: raise ValueError("numeric source digest differs")
    compiler = record["compiler"]
    required = {"schema": "gooo/build-identity/v1", "language": "gooo", "version": "0.6.32-dev",
                "go_version": "go1.27.2", "native_go_required": "go1.27.2",
                "compiler_source_sha": PIN, "source_status": "CLEAN_VCS",
                "vcs_revision": PIN, "vcs_modified": "false", "build_info_observed": True}
    if any(type(compiler.get(k)) is not type(v) or compiler.get(k) != v for k, v in required.items()):
        raise ValueError("numeric compiler source identity differs")
    if source[prefix + "compiler-version.txt"].decode().strip() != PIN:
        raise ValueError("numeric compiler pin differs")
    expected.update(generation_sha256=digest(raw), compiler_identity_sha256=digest(raw_member(raw, "compiler")),
                    activity_receipt_sha256=digest(raw_member(raw, "activity")), compiler_source_sha=PIN,
                    json_input_sha256=json_input)
    return expected
