# Integer bounds example

These synthetic export plans have row limits -1, 0, 100, 499, 500 and 501.
Two recipe-v2 policies retain the same lower bound 0 and change the upper
bound from 1000 to 500. Both bounds are required alongside action,
destination, dry-run and format.

Follow the [private setup and comparison instructions](../../docs/artifact-int64-bounds.md).
Case paths must be replaced with your own clean physical absolute paths.
Expected digests are explicit fixture expectations, not calculated from the
artifact during setup. The wrong-string fixture demonstrates a mandatory type
failure; it cannot reach the numeric relation.

Comparison and replay are local historical observations. The authenticated
artifact gate uses its own immutable configuration without per-request human
approval and performs only its declared local state transition. No export or
external API is executed by these examples.
