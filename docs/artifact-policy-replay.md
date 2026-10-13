# Recheck a saved artifact-policy comparison

`policy-impact replay --report FILE` rederives both historical judgments in a
saved [artifact-policy comparison](artifact-policy-impact.md). Use it when you
need to revisit a policy change after the original inputs have been removed
or replaced. It reads the private report and uses its retained artifact bytes;
it does not read the original case, policy, or artifact paths.

Exit `0` means the entire historical comparison is internally consistent with
the matching implementation. A side that was denied remains a valid historical
denial. Replay does not grant permission, authenticate a principal or issuer,
read a live gate, change a request, or execute an API/export operation. It adds
no individual human approval step to the machine gate.

## Run a comparison, remove its copied inputs, then replay

This workflow requires the current repository source. Build the CLI from the
repository root; an older preview package does not include this command:

```sh
go build -trimpath -o bin/policy-impact ./cmd/policy-impact
```

Copy the four synthetic [example files](../examples/artifact-impact/README.md)
into a new private directory. The following setup uses Python 3's standard
library and changes only the artifact path in the copied case. It keeps the
operator-selected expected SHA-256, rather than trusting a new digest computed
from an arbitrary replacement artifact.

```sh
impact_demo="$(mktemp -d)"
impact_demo="$(cd "$impact_demo" && pwd -P)"
chmod 700 "$impact_demo"
cp examples/artifact-impact/case.json \
  examples/artifact-impact/artifact.json \
  examples/artifact-impact/policy-internal.json \
  examples/artifact-impact/policy-external.json "$impact_demo/"
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

./bin/policy-impact compare \
  --case "$impact_demo/case.json" \
  --before "$impact_demo/policy-internal.json" \
  --after "$impact_demo/policy-external.json" \
  --report "$impact_demo/newly-denied.report.json"

./bin/policy-impact compare \
  --case "$impact_demo/case.json" \
  --before "$impact_demo/policy-external.json" \
  --after "$impact_demo/policy-internal.json" \
  --report "$impact_demo/newly-allowed.report.json"
```

The first report has direction `newly_denied`: before would admit the synthetic
internal export plan, after would reject it. The reversed comparison is
`newly_allowed`, an access expansion for this declared case. Each comparison
captures the artifact once and saves a separate complete report. Neither
comparison exports the plan.

After both comparisons succeed, remove only the four copied inputs. Keep the
reports in their private directory and run replay in the same terminal:

```sh
rm "$impact_demo/case.json" \
  "$impact_demo/policy-internal.json" \
  "$impact_demo/policy-external.json" \
  "$impact_demo/artifact.json"

./bin/policy-impact replay --report "$impact_demo/newly-denied.report.json"
./bin/policy-impact replay --report "$impact_demo/newly-allowed.report.json"
```

The repository examples remain intact. Both replay commands should exit `0`
and report `status: verified` with `code: HISTORICAL_COMPARISON_MATCH`. Their
directions and before/after decisions remain historical values, including the
denied side. If both sides reject, direction is still `unchanged`; separate
before/after decisions and reasons describe that case.

## What is rederived

Replay validates the complete typed report, its canonical content ID, and the
original comparison implementation identity. It rederives both contexts and
policy versions, each producer observation from retained bytes, every evidence
fact and compiled Gooo decision, all completion records and ordered steps,
the proposed approval/control-plane effect checks, final judgments, the
difference, and the historical audit. It checks the common base-policy receipt
and preserves its original timestamp.

The original `observation_unix` supplies evidence time. The current wall clock
does not decide historical freshness: a previously allowed case can verify
after its artifact deadline has passed. Replaying a report does not renew that
deadline or permit a new operation. No CLI flag can supply a replacement clock,
principal, policy, pass result, or effect budget.

The report retains typed case/policy values and their semantic digests, so these
digests can be recomputed. It retains the raw input digests without retaining
the original case/policy JSON bytes. Replay checks those raw digests' format and
internal bindings; it cannot independently recover the original formatting or
prove which original JSON file produced them. Retained artifact bytes are
separately re-observed against the configured digest, schema, types, and claims.

The host handles private file reading, historical/context/source bindings,
ownership, and equality checks. Compiled Gooo supplies the base, evidence,
completion, effect-budget, and final relations. The command uses the existing
Gooo rules and compiler projections; it does not change the language engine.

## Source compatibility and private output

The comparison identity includes the original comparison source roster,
artifact producer/parser and compiled rule bindings, Go runtime version,
operating system, and architecture. They must match the current verifier's
comparison identity. Changed sources or a different runtime/platform reject
explicitly; there is no silent conversion of a historical report.

The replay verifier has a separate source identity. Adding replay does not
replace the original comparison identity or alter its eight source files.
`verifier_sha256` in the summary identifies this verifier's public source
binding. It is not an issuer signature or the private report's digest.

The report must be a stable regular file with mode `0600`, no final-file
symlink, and size at most 64 MiB. Parent aliases are resolved and the parent
and file identities are checked during reading. Keep it in a private directory. Strict
decoding rejects unknown, missing, duplicate, null, invalid-Unicode, or trailing
JSON content. The report can contain private principal/request facts, paths,
predicate values, and artifact bytes; do not publish it as a safe summary.

Replay creates no output file and does not modify the report or its directory.
Standard output is one bounded JSON summary with schema
`policy-studio/artifact-impact-replay-summary/v1`. A verified summary includes
the before/after decisions and aggregate counts, direction and difference
counts/configuration flags, and the public verifier binding. It does not print
private paths, IDs, predicate values, retained bytes, or report/input hashes.
It declares `historical: true`, `simulation: true`, `read_only: true`,
`authenticated_server_state: false`, `committed: false`,
`target_effects_executed: false`, and `current_artifact_reads: 0`.

| Exit | Meaning |
| --- | --- |
| `0` | Complete historical comparison matched. **Never a current execution grant.** |
| `2` | CLI, private report, strict JSON, source, or historical consistency failure. |

Failures use fixed codes: `USAGE_INVALID`, `REPORT_FILE_INVALID`,
`REPORT_JSON_INVALID`, `REPORT_REPLAY_INVALID`, or `REPLAY_SOURCE_INVALID`.
They do not print private parsing details or paths. An empty or partial file
left by a failed comparison is not a replayable completed report.

## Limits of an unsigned historical record

This checks internal consistency, not authenticity. Someone who can rewrite
an unsigned report coherently and recompute all bindings may produce another
internally consistent history. Source hashes do not prove who issued the report
or that the claimed historical acquisition, file sync, or external event
actually happened. The saved audit describes the original reservation and
planned write; replay does not certify physical historical persistence.

A passing replay does not establish current file existence, permission,
configuration, policy completeness, universal safety, customer adoption, or
exactly-once external execution. Use the
[private prepare/submit client](policy-client.md) for a new request to an
authenticated configured machine gate. A comparison report is unsigned
simulation data and cannot serve as that gate's admission command.
