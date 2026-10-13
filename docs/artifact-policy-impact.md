# Compare two artifact policies before deployment

`policy-impact compare` applies two proposed artifact policies to one captured
local file. It shows which required conditions and effect-budget checks change,
and whether the same case becomes newly allowed or newly denied. Use it to
review a configuration change before creating a fixed
[v2 artifact gate](artifact-gate.md).

This is an unsigned local simulation. It does not authenticate the proposed
principal, read a running server's configuration, grant permission, change a
request state, or execute an API/export operation. Its report always declares
`simulation: true`, `authenticated_server_state: false`, `committed: false`,
and `target_effects_executed: false`. Live machine requests continue to use
the [private prepare/submit client](policy-client.md); no individual human
approval prompt is added.

## Run the synthetic example

From the repository root, build the comparator:

```sh
go build -trimpath -o bin/policy-impact ./cmd/policy-impact
```

Copy the [example files](../examples/artifact-impact/README.md) into a new
private directory. The case must point to a clean **physical absolute path**.
The setup below changes only that path in the copied case. It keeps the explicit
trusted expected SHA-256; it does not derive an expected digest from the file
being tested. The setup uses Python 3's standard library.

```sh
impact_demo="$(mktemp -d)"
impact_demo="$(cd "$impact_demo" && pwd -P)"
chmod 700 "$impact_demo"
cp examples/artifact-impact/*.json "$impact_demo/"
chmod 600 "$impact_demo/"*.json

python3 - "$impact_demo" <<'PY'
import json
import sys
from pathlib import Path

directory = Path(sys.argv[1])
case_file = directory / "case.json"
case = json.loads(case_file.read_text())
case["artifact"]["path"] = str(directory / "artifact.json")
case_file.write_text(json.dumps(case, indent=2) + "\n")
case_file.chmod(0o600)
PY
```

The file is a synthetic export plan whose destination is `internal`. Both
policies check the same five fields. Changing the required destination from
`internal` to `external` excludes this captured case:

```sh
./bin/policy-impact compare \
  --case "$impact_demo/case.json" \
  --before "$impact_demo/policy-internal.json" \
  --after "$impact_demo/policy-external.json" \
  --report "$impact_demo/newly-denied.report.json"
```

The comparison direction is `newly_denied`. The before side would admit the
case; the after side would reject it because `destination_equal` observes
`internal` where that policy requires `external`. Both sides retain all five
observations, including the four unchanged passing conditions.

Standard output is one JSON summary with schema
`policy-studio/artifact-impact-summary/v1`. A saved comparison reports
`status: compared`, `code: COMPARISON_SAVED`, `simulation: true`, and
`report_saved: true`. Its `before` and `after` contain `would_admit`, a fixed
reason label, and claim counts. The summary also reports the direction and
counts of added, removed, and changed claims; detailed values stay private.

Reverse the policies to see the same case become newly allowed:

```sh
./bin/policy-impact compare \
  --case "$impact_demo/case.json" \
  --before "$impact_demo/policy-external.json" \
  --after "$impact_demo/policy-internal.json" \
  --report "$impact_demo/newly-allowed.report.json"
```

This is an access expansion for the declared case. A new allowance is not
inherently a safer or better policy. Neither command sends the plan anywhere
or creates a live approval. Each invocation captures the file once; the second
invocation is a separate comparison.

The artifact bytes have the explicit expected digest
`sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533`.
The deadline `4102444800` is a demo value in 2100, not a recommended production
validity period. The checked conditions are exact equalities, not row-limit
inequalities or a complete export-security policy.

## Inputs and limits

The case schema is `policy-studio/artifact-impact-case/v1`. Its required fields
are `schema`, `request`, `principal`, `base_rules`, and `artifact`. The artifact
holds the selected path, explicit `expected_sha256`, and positive
`deadline_unix`. The request and principal are operator-selected scenario facts;
they are not read from an authenticated server. The scenario assumes a new
pending request.

Each candidate uses `policy-studio/artifact-admission-policy/v1`, including a
recipe with 1–256 required claims. The following values must match exactly:

| Shared value | Purpose |
| --- | --- |
| `recipe.max_bytes` | One opaque acquisition has one byte bound. |
| `required_authority` | Both sides ask the same evidence-authority question. |
| `max_age_seconds` | Both sides use the same freshness policy. |
| `control_plane_budget` | Both sides require the same proposed denial-record effects. |

Policy ID/revision, artifact schema, configured fields, predicates/claim order,
and approval budget may differ. Every recipe still checks the actual digest, exact flat JSON schema
and field set, and all configured types. Dropping a claim cannot bypass those
mandatory checks. Supported field types are `text`, `bool`, and `int64`.

Case and policy files are bounded to 1 MiB each and must be stable regular files
with mode `0600`. Ambiguous JSON, duplicate keys, unknown or missing fields,
explicit nulls, invalid Unicode, unsupported recipes, and mismatched shared
values are rejected. The artifact bound is 1–65,536 bytes, with at most 255
configured fields. The private report is bounded to 64 MiB. Linux and macOS
are the supported hosts.

Use operator-trusted case/policy files and expected digests. The comparator
does not decide which expected digest your organization should trust, verify
an issuer signature, or prove that a proposed principal is currently enabled.

## One acquisition, two complete judgments

The host evaluates the common base rules with compiled Gooo and separately
records the proposed principal's eligibility. If the proposed principal is
disabled, lacks execution permission, or the common base policy rejects,
the artifact is not read. Both policies receive full unknown-claim records.
The base Gooo result is preserved; proposed permission failure is not relabeled
as a different base-policy result.

Otherwise, the built-in reader acquires the bounded regular file once and
rejects symlink/non-regular sources and detected changes during acquisition.
Each recipe observes that same owned acquisition. One host timestamp is
shared by both observations and decisions. A report describes the captured
input at that time; it does not authorize a later read or execution.

For each policy, the report retains:

- The producer's actual retained bytes, mandatory checks, and every ordered claim.
- Every evidence fact and compiled Gooo `EvidenceAdmission` decision.
- Every completion step, final count, coverage result, and readiness decision.
- Proposed approval/control-plane effects, budgets, and `EffectBudgetAccepts` decisions.
- Final facts and the compiled Gooo `ArtifactGateAdmits` decision.

The host supplies acquisition, scenario/source/context bindings, the sampled
time, claim coverage, and report construction. Compiled Gooo evaluates the
base rules, evidence admission, completion fold/readiness, effect budgets, and
final relation. This unit adds a comparison composition; it changes neither
the Gooo engine nor the existing gate/compiler/generated rules.

## Read the difference accurately

The direction is `newly_allowed`, `newly_denied`, or `unchanged`, based on
proposed permission and the final hypothetical decisions. A reason can change
even when both policies reject.

Added claims follow after-policy order; removed claims follow before-policy
order. Changed common claims follow before-policy order and describe actual
predicate/schema/type, observation, or evidence-decision differences. Relative
order changes among common claims are separate from added and removed claims.
Context digests, evidence IDs, policy ID/revision,
and input whitespace can alter bindings without becoming a changed claim.

Effect-budget value differences are separate from changes in the ten derived
effect checks. Changing an unused budget flag may change configuration while
leaving the hypothetical decision unchanged. An approval budget that forbids
target mutation can newly deny a case even when all artifact claims pass.

The proposed approval operation changes local target/session state and writes
the filesystem; the proposed denial-record operation changes session state and
writes the filesystem. Both are evaluated as idempotent gate operations.
**The comparator performs neither operation.** Its actual effects are reading
the operator inputs, optionally reading the artifact, and writing a new report.
Reads are audited separately because the effect record has no read category.

## Private output and exit codes

The full report can contain private request/principal facts, artifact bytes,
predicate values, and paths. Keep it in a private directory. Default output
is a bounded summary and does not print those contents.

`--report` is required. Configuration and physical input/output alias checks
precede reservation of a new `0600` report. Reservation occurs before artifact
acquisition. Existing files are preserved; report creation is exclusive and
successful writes synchronize the file and parent directory.

The serialized audit records report reservation and planned report writing;
it cannot attest a later successful sync or close. The summary sets
`report_saved: true` only after writing, synchronization, and close succeed.

| Exit | Meaning |
| --- | --- |
| `0` | A complete comparison report was saved. **Never an execution grant.** |
| `2` | Configuration, source/host, private-file, output, or comparison failure. |

A digest mismatch, read failure, oversized artifact, or failed predicate
reported by the artifact producer can produce a complete denied comparison and
exit `0`. If input/output alias or parent validation cannot be established,
the command instead fails before artifact capture with exit `2`. A report
write/sync failure returns `2` and may leave the reserved empty or partial file.
Such a file is not a completed report. Preserve it for inspection and use a new
report path for another invocation; the command never overwrites it.

The report is content/source bound but unsigned. It is not a
`policy-studio/admission-outcome/v2`, and the four-field admission API does not
accept it. It does not migrate a live policy, update a server snapshot, rotate
credentials, run external tools, or provide exactly-once external execution.
The declared finite cases do not establish policy completeness, universal
safety, customer adoption, or suitability for every API workflow.
