# Try the integer bounds and explanation kit

This separately versioned experimental kit lets you compare two policies over
one synthetic export plan, retain the judgment after deleting the copied inputs,
and read a private HTML explanation. The executable includes the existing
compiled Gooo numeric decisions; Go handles JSON, files and rendering.

Running the kit needs ZIP extraction, a POSIX shell and standard Mac/Linux tools:
`awk`, `cat`, `chmod`, `cp`, `dirname`, `mktemp`, `mv`, `rm`, `sed`, `uname`,
`wc`, and `sha256sum` or `shasum`. It needs no Go, Python, Gooo compiler,
server, account, token or network connection. A browser can open the saved HTML
locally without JavaScript or remote resources.

## Choose the bounds-profile download

The [published `policy-impact-bounds-v0.1.0-preview.1` preview](https://github.com/kimjooyoon/gooo-policy-studio/releases/tag/policy-impact-bounds-v0.1.0-preview.1)
is an **integer bounds and explanation kit** with manifest schema
`policy-impact-kit/v2` and profile `artifact-bounds/v1`.
Choose `policy-impact-bounds-darwin-arm64.zip` for macOS arm64 or
`policy-impact-bounds-linux-amd64.zip` for Linux amd64. Other targets are not
defined for this kit.

The older `policy-impact-v0.1.0-preview.1` release remains sealed at
`0f17df330fe4f3648f6e1d1c7b1e26ca28de9d46`. It demonstrates equality comparisons
and replay; it does not contain these integer bounds or the explanation command.
The separate Studio server/gate release assets are also a different distribution.

Before extracting or running, compare the archive SHA-256 with the checksum
declared for that exact release asset:

```sh
shasum -a 256 policy-impact-bounds-darwin-arm64.zip
# Linux: sha256sum policy-impact-bounds-linux-amd64.zip
```

Use your usual ZIP tool to extract into a new directory. Then:

```sh
cd policy-impact-kit
./try-demo.sh
```

The script checks the target, bounds profile and complete bundled checksum list
before invoking the executable. Checksums are unsigned byte-consistency records;
the bundled list alone does not authenticate the publisher. Keep normal OS
protections enabled. Do not disable quarantine or other protections to run it.

## Follow the row 501 judgment

The demo creates a fresh private physical `/tmp/gooo-policy-impact-bounds.*`
directory (`/private/tmp/...` on macOS), with mode `0700`. It copies four public
synthetic inputs with mode `0600`, changes exactly one copied artifact path and
preserves the explicit expected artifact SHA-256. It then makes three calls:

1. Compare row 501 under the before policy `0..1000` and after policy `0..500`.
   The before judgment is `ADMITTED` with six passing claims. The after judgment
   is `EVIDENCE_REJECTED` with five passes and one failure: `row_limit_at_most`.
   The direction is `newly_denied`; the lower bound of zero still passes.
2. Delete only those four private copied inputs and replay the saved comparison.
3. Replay-verify the saved report again and write `explanation.html` as a new
   private file. The report retains its historical observation time.

These are the fixed synthetic example's expected results, not a report of a
customer trial. Original Gooo evaluates the numerical relation. The HTML copies
the verified facts and decisions, including all five numeric outputs and their
source bindings; it does not introduce a second numerical rule.

The final JSON line gives `work_directory`. Open `explanation.html` inside that
directory using your normal browser or file viewer. The summary and changed
claim table are visible; expand the details to inspect claims, evidence,
completion, effects and source bindings. A predicate pass count alone is not
execution permission.

The directory also retains `comparison.report.json`, three summaries, per-call
diagnostics, `product-calls.tsv`, `digests.tsv` and `inputs.deleted`. Reports,
HTML and diagnostics are private `0600` files. Reports retain artifact bytes,
policy facts and paths; the HTML contains private case values. Review these
before sharing. The script retains diagnostics on failure, installs nothing
and never overwrites an existing report or HTML. Remove the private demo
directory manually when no longer needed.

Compare exit 0 means a report was saved, including a denied judgment. Replay
exit 0 means historical consistency with matching sources, Go runtime and host.
Explain exit 0 means that checked historical explanation was saved. None grants
current authorization, changes a running policy or executes an API/export.
The configured machine gate still evaluates its policy without individual
human approval; this offline demo does not connect to or commit that gate.

## Version and platform limits

The package's committed source snapshot is recorded separately from the actual
binary build metadata in `manifest.json` and `buildinfo.txt`. Assembly copies an
existing binary. The reused Mac executable was built from
`65242c17585a8e4a93ecc31f49b005896d715039` with `vcs.modified=true` and
`CGO_ENABLED=1`. Its matching compiled source and renderer bindings are checked
against the package snapshot; it is not a clean-main/tag or reproducible build.

No macOS Developer ID signing, notarization, cold browser-download quarantine
success or tested minimum macOS version is claimed. The executable may depend
on system dynamic libraries. A blocked launch is useful first-use feedback;
keep protections enabled. Linux validation is limited to the repository's
Ubuntu amd64 CI environment. Other distributions, musl and static linkage are
not established. This guide makes no broader host support claim.

Historical replay requires matching implementation, Go runtime and OS/architecture.
An old report cannot be silently migrated into this version or a current grant.
Retain earlier histories with their original binary. The kit provides no
portable historical mode, artifact issuer authentication or universal safety
guarantee. Three CLI calls are not a measured native-call count: source identity
probes and replay can execute compiled rules and read the host clock while
preserving the historical evidence time.

The kit preserves the project MIT, Go BSD and morluto Rea MIT licenses under
`notices/`. Gooo is independent; Google does not endorse the project. Complete
public sources are under `source/`, excluding private reports, tokens, toolchains
and build outputs. Follow relative repository links using `source/docs/` and
`source/examples/`. See the [bounds contract](artifact-int64-bounds.md),
[comparison contract](artifact-policy-impact.md), [replay contract](artifact-policy-replay.md)
and [explanation contract](artifact-policy-explain.md) before adapting inputs.

For a first-use question, report your OS/architecture, exact release or source
commit, command and fixed error code with a minimal synthetic example in the
repository's Issues. Do not attach tokens, private reports or private HTML.
This finite workflow illustrates a possible use; it is not customer adoption
or production safety evidence.
