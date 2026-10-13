# Read a verified historical policy comparison

`policy-impact explain` saves a private HTML explanation of a saved comparison.
It first verifies the complete report with the existing compiled Gooo rules,
then shows the verified before/after judgments, required claims, evidence,
completion and effect budgets. It does not select or change a running policy.
The before/after summary and changed claim results appear first. Detailed
verification data stays available in expandable sections.

Use the [integer bounds example](artifact-int64-bounds.md) to prepare a private
comparison report. Build the current source with Go 1.27.2; the generated Gooo
code is included, so viewing an explanation needs no compiler regeneration.
The separate [numeric bounds kit walkthrough](artifact-bounds-first-use.md)
also prepares and explains the same synthetic comparison without Go or Python.

```sh
go build -trimpath -o bin/policy-impact ./cmd/policy-impact
./bin/policy-impact explain \
  --report "$bounds_demo/row-501.report.json" \
  --output "$bounds_demo/row-501.explanation.html"
```

`bounds_demo` is the private directory prepared in the linked example. Both
flags are required, the report must be a bounded regular `0600` file, and the
output must be a new file in an existing directory. Existing output files are
never overwritten. Open the saved HTML locally; it needs no JavaScript, remote
assets, account or running server.

## Follow the judgment through every stage

For row 501, the original upper bound of 1000 passes and the proposed bound of
500 fails. The lower bound of 0 still passes. The numeric detail retains the
exact value, bound and operator, all five Gooo outputs and their source
bindings. The explanation copies these checked judgments; it does not replace
them with another numerical rule.

A failed claim is only one possible reason for denial. Evidence may have
expired even when every predicate passes. Completion may not be ready, or the
declared effect budget may forbid the proposed operation. A disabled principal
or rejected base request can prevent artifact acquisition altogether. The
before/after sections preserve those separate judgments and the final reason.
They do not infer permission from predicate pass counts.

`Not executed` means that a claim has no numeric proof. Equality claims do not
use the numeric relation, and mandatory acquisition, digest, schema or type
failures prevent it from running. An absent proof never means that the
numeric predicate passed.

## Keep the explanation private

The HTML intentionally contains selected claim names and expected/actual
values. It is a private diagnostic document, not an automatically safe public
summary. It omits retained raw artifact bytes, arbitrary local input paths,
report IDs and raw input hashes. Untrusted text is escaped, and the document
has no scripts, remote resources or action controls.

The terminal receives only fixed labels, bounded counts, booleans and public
source fingerprints. `local_file_write_declared: true` describes this command's
local output effect; `output_saved: true` appears only after successful writing,
syncing and closing. The explanation writes a file, so `read_only` is false.
`current_artifact_reads` stays zero: original case, policy and artifact paths
inside the report are historical data and can already have been deleted.

Exit 0 means a verified explanation was saved, including explanations of
denied judgments. Exit 2 means a fixed usage, report, rendering or output
failure. A late output failure may leave an exclusively reserved empty or
partial `0600` file. It does not report successful saving or overwrite an
existing explanation.

## Preserve historical scope

Verification retains the saved observation time and does not refresh evidence.
It executes compiled relations; existing source-identity probes may also read
the host clock. The renderer does not acquire a new evidence clock. Source
fingerprints identify implementation consistency, not a publisher signature.
Coherently rewritten unsigned history can remain internally consistent.

The renderer has a separate source identity. The comparison and replay
identities are unchanged by this presentation feature, so matching reports
from the current numeric implementation can still be explained. Earlier
implementation histories remain subject to the existing source, runtime and
host checks; there is no automatic migration.

The published `policy-impact-v0.1.0-preview.1` download kit is sealed at
`0f17df330fe4f3648f6e1d1c7b1e26ca28de9d46`. It contains equality comparisons
and replay, but does not contain integer bounds or this explanation command.
For these features, use the
[published `policy-impact-bounds-v0.1.0-preview.1` preview](https://github.com/kimjooyoon/gooo-policy-studio/releases/tag/policy-impact-bounds-v0.1.0-preview.1)
with the [bounds kit walkthrough](artifact-bounds-first-use.md), or the current
source instructions above.

An explanation is a historical simulation, not current authorization,
authenticated server state or execution of an API/export. Machine admission
continues to use its configured policy without a person approving each request.
This finite example has no customer or production safety claim.
