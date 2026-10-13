# One artifact, two proposed policies

Follow the [comparison guide](../../docs/artifact-policy-impact.md) to build
`policy-impact`, copy these files into a fresh private directory, set the
copied case's physical absolute artifact path, and make the inputs `0600`.
The placeholder path in `case.json` is not a usable artifact location.

| File | Role |
| --- | --- |
| `case.json` | One proposed machine principal/request, common base rules, explicit artifact SHA and demo deadline. |
| `artifact.json` | A synthetic internal export plan; no real data or credentials. |
| `policy-internal.json` | Five exact predicates, including destination `internal`. |
| `policy-external.json` | The same common constraints; destination predicate requires `external`. |

The artifact is the original valid export-plan example byte for byte. Its
expected SHA-256 is
`sha256:462147ef4a0025b680de1337e78fd91e04a0fa3bd8aae3d438024000839db533`.
Do not calculate a new trusted expected digest from an arbitrary replacement
file. The deadline `4102444800` is a synthetic 2100 date and must be replaced
with an appropriate operator policy for real use.

With `policy-internal.json` as before and `policy-external.json` as after,
this same artifact is newly denied. Reverse them to show a new allowance.
Each report retains both full sets of observations. The changed predicate is
`destination_equal`; the other four conditions continue to pass. No plan is
exported and no destination is contacted.

A new allowance is an access expansion for this declared case, not proof that
a policy is safer. Exit `0` only means the complete private comparison was
saved. The result is unsigned, uses proposed facts, and cannot serve as a live
admission command or approval. Keep full reports private and use a new report
path for each invocation.
