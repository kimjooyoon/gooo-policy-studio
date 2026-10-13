# Bound an automation input with Gooo

An export plan with `row_limit: 100` should satisfy a declared `0..500`
limit. Checking equality with `500` would reject that valid input. Recipe v2
supports two independent required integer conditions, `field_int64_gte/v1`
and `field_int64_lte/v1`. Compiled Gooo calculates the ordering, result and
reason; Go handles strict parsing, bounded file acquisition and bindings.

These conditions work through the existing producer, authenticated local
[artifact gate](artifact-gate.md), [policy comparison](artifact-policy-impact.md)
and [historical replay](artifact-policy-replay.md). The gate uses its server's
fixed policy without a person approving each request. A comparison or replay
does not change a running policy, grant permission or execute an export/API.

## Declare both bounds

Use `policy-studio/artifact-recipe/v2` with producer `flat-json/v2`.
Numeric predicates require an explicitly configured `int64` field. The four
claim fields stay unchanged:

```json
{
  "id": "row_lower",
  "verifier": "field_int64_gte/v1",
  "field": "row_limit",
  "expected": "0"
}
```

```json
{
  "id": "row_upper",
  "verifier": "field_int64_lte/v1",
  "field": "row_limit",
  "expected": "500"
}
```

Both are required claims. An upper bound alone accepts negative values.
`expected` is a canonical signed decimal string within int64: `+1`, `-0`,
leading zeroes, fractions, exponents and overflow are rejected. Numeric
predicates on text or Boolean fields, unknown verifiers and numeric predicates
under recipe v1 are rejected before artifact acquisition. Recipe v1 remains
restricted to `field_equals/v1`; recipe v2 can also use that equality predicate.

## Try a limit change

For a separately assembled preview that needs no Go or Python, follow the
[numeric bounds kit walkthrough](artifact-bounds-first-use.md). The source
instructions below remain available for building and preparing your own copies.

The [synthetic fixtures](../examples/artifact-int64-bounds/) require six
conditions: action, destination, lower bound, upper bound, dry-run and format.
The before policy allows `0..1000`; the after policy allows `0..500`.
Row 501 becomes newly denied, and reversing the policies makes it newly allowed.
Rows 0, 100, 499 and 500 satisfy both; row -1 fails both lower bounds.

Build this source version with Go 1.27.2. Generated Gooo code is included;
the Gooo compiler is needed only to regenerate that code.

```sh
go build -trimpath -o bin/policy-impact ./cmd/policy-impact
bounds_demo="$(mktemp -d)"
bounds_demo="$(cd "$bounds_demo" && pwd -P)"
chmod 700 "$bounds_demo"
cp examples/artifact-int64-bounds/*.json "$bounds_demo/"
chmod 600 "$bounds_demo/"*.json
python3 - "$bounds_demo" <<'PY'
import json
import sys
from pathlib import Path

directory = Path(sys.argv[1])
for case_file in directory.glob("case-row-*.json"):
    case = json.loads(case_file.read_text())
    case["artifact"]["path"] = str(directory / case_file.name.replace("case-", "artifact-"))
    case_file.write_text(json.dumps(case, indent=2) + "\n")
    case_file.chmod(0o600)
PY
./bin/policy-impact compare \
  --case "$bounds_demo/case-row-501.json" \
  --before "$bounds_demo/policy-before-upper-1000.json" \
  --after "$bounds_demo/policy-after-upper-500.json" \
  --report "$bounds_demo/row-501.report.json"
./bin/policy-impact replay --report "$bounds_demo/row-501.report.json"
```

The setup changes copied paths only. It preserves each explicit expected
SHA-256 instead of trusting whatever bytes happen to be present. The example
deadline in 2100 is a demo value; choose a validity period for your own work.
Compare exit 0 means a comparison was saved, including a denied judgment;
it is not a current execution grant. Invalid configuration returns exit 2.

To read the verified claim and stage details without searching the raw JSON,
save a [private historical explanation](artifact-policy-explain.md) with
`policy-impact explain --report FILE --output NEW_PRIVATE_HTML`.

## Retain the actual judgment

Every executed numeric claim includes `native_proof` with typed `facts`
(`value`, `bound`, `operator`), the full `decision` (`at_most`, `at_least`,
`operator_ok`, `matched`, `reason`) and actual source/generated/bridge/
generation/compiler bindings. Gooo computes both comparisons even when an
unsupported operator is supplied to the native relation. An unknown operator
returns `matched: false` and `UNSUPPORTED_OPERATOR`; recipes cannot select it.

The public recipe selects `lte` or `gte` through its registered verifier.
Successful matches use `BOUND_MATCH`; valid nonmatches use `BOUND_MISMATCH`.
Equality claims have no numeric proof. Failed mandatory digest, schema, type
or acquisition checks prevent numeric execution and also have no numeric proof.
An absent proof is never evidence that a numeric predicate passed.

New producer reports use `policy-studio/artifact-preflight/v2`, including
reports from a legacy equality recipe. The report producer ID matches the
selected recipe; implementation identity is separately versioned as
`policy-studio/artifact-producer-source/v2`. Replay rederives all numeric facts
and decisions from the trusted recipe and retained bytes. Rehashing a forged
judgment does not make it a valid judgment.

Reports retain raw bytes and local paths and may contain private business
facts. Keep complete reports private with mode `0600`; share synthetic source
or deliberately safe summaries. Replay remains unsigned historical consistency
checking for the matching implementation, Go runtime and host platform. It
does not authenticate an issuer or assert that a file is still present.

## Keep old histories with their original version

Source-bound reports and gate snapshots from an earlier implementation are
rejected by this implementation. Preserve them with their original binary, or
create fresh state from reviewed configuration for the new source version.
There is no silent migration or conversion of old judgments into new grants.

The published `policy-impact-v0.1.0-preview.1` download kit is sealed at commit
`0f17df330fe4f3648f6e1d1c7b1e26ca28de9d46` and implements equality recipes.
It does not contain these bounds. Use the new source instructions above for
this feature; an old download or proof is not validation of the new feature.

This finite local example is a workflow hypothesis, with no customer or
production safety claim. External effects, authentication and immutable
policy selection remain responsibilities of the surrounding system.
