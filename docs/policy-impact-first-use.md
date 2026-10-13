# Try the Policy Impact kit

The experimental kit contains an existing `policy-impact` executable and four
public synthetic inputs. You can compare two proposed policies over the same
artifact, delete those inputs, and verify the retained judgments. Running the
demo needs ZIP extraction, a POSIX shell, and the standard Mac/Linux tools
`mktemp`, `awk`, `sed`, `chmod`, `uname`, plus `sha256sum` or `shasum`; it
does not need Go, a compiler, Python, a server, an account or a token.

Choose the archive for **macOS arm64** (`policy-impact-darwin-arm64.zip`) or
**Linux amd64** (`policy-impact-linux-amd64.zip`). Verify its SHA-256 against the
declared release asset checksum, extract into a new directory using your usual
ZIP tool, then run:

```sh
shasum -a 256 policy-impact-darwin-arm64.zip
# Linux: sha256sum policy-impact-linux-amd64.zip
```

Compare that hash with the release's independently declared archive checksum
before extracting or running it. After extraction:

```sh
cd policy-impact-kit
./try-demo.sh
```

The script checks its bundled checksums and target before invoking the binary.
It creates a fresh private `/tmp/gooo-policy-impact.*` directory (a physical
`/private/tmp` path on macOS), copies the four inputs with mode `0600`, and
changes only the copied case's artifact path. The expected artifact digest
remains the operator-selected digest supplied in the public example.

The four calls are:

1. Compare an internal-destination policy with an external-destination policy.
   The artifact still says `internal`, so this change is `newly_denied`.
2. Compare the policies in reverse: the result is `newly_allowed`.
3. Delete only the four private copied inputs and replay the denied comparison.
4. Replay the allowed comparison using its retained report.

The final line identifies the private working directory. It contains two full
`0600` comparison reports, four safe summaries, per-call diagnostics,
`product-calls.tsv`, `digests.tsv`, and `inputs.deleted`. Reports preserve
artifact bytes, proposed policy facts and paths; review them before sharing.
The script keeps the directory and diagnostics on failure, does not install
anything, and does not change your `HOME`, `CODEX_HOME` or existing reports.
Remove the demo files manually when you no longer need them.

Both comparisons exit successfully when a report is saved, including a denied
judgment. Replay success means unsigned historical consistency with this
implementation. It does not grant current execution permission, authenticate
an artifact issuer, execute an API call, or establish general safety. Historical
replay still requires matching comparison sources, Go runtime version and
OS/architecture. This kit adds no portable historical mode.

For your own bounded artifact, use the [comparison contract](artifact-policy-impact.md)
and [historical replay contract](artifact-policy-replay.md). These document
the exact flat JSON types, operator trust boundaries, private-file requirements
and full report fields. The demo is a synthetic workflow, not customer or
production adoption evidence. The repository guides retain their original
relative paths: use their complete copies under `source/docs/` and examples
under `source/examples/artifact-impact/` when following those paths.

## Build and download limits

`manifest.json` records the package's clean committed source snapshot separately
from the binary's actual build record. `buildinfo.txt` preserves the Go version,
module version, VCS revision, dirty flag, CGO setting and build flags observed in
the executable. Assembly copies the binary; it does not rebuild it at the
package commit. In particular, the reused macOS candidate was built from
`cefde40ee8b7c1d487a620988f80346c5659988b` with `vcs.modified=true` and
`CGO_ENABLED=1`. It must not be described as a clean-main/tag or reproducible
build. The source-bound comparison and replay identities remain independently
checkable against the included source snapshot.

macOS Developer ID signing, notarization and downloaded quarantine behavior
are not claimed. The reused executable can depend on system dynamic libraries.
An observed development host version `26.5.2` and load stamp `13.0` do not
establish a tested minimum macOS version. Keep normal operating-system
protections enabled; the kit makes no security overrides. A blocked launch is
a useful first-use failure to report. Other OS/architecture combinations have
no kit support claim.

Linux execution is checked on the repository's Ubuntu CI runner; compatibility
with other distributions or musl has not been established. Inspect actual CGO
settings; this is not a static-binary claim.

Bundled checksums detect bytes differing from the bundled list. They are
unsigned, so verify the archive against independently obtained declared asset
checksums as well. Neither a checksum nor a source identity authenticates the
publisher or the historical physical event.

The kit includes the project MIT license, Go BSD license and preserved morluto
Rea MIT notice under `notices/`. Gooo is an independent language project;
Google does not endorse this kit. The `source/` directory contains only the
package commit's tracked public source files, excluding private reports,
tokens, toolchains and build outputs.

## Copy-only assembly and validation

Maintainers can assemble an already built binary without running it:

```sh
python3 tools/package-policy-impact-kit.py \
  --binary bin/policy-impact --buildinfo policy-impact-buildinfo.txt \
  --target linux/amd64 --source-ref FULL_COMMIT \
  --out-dir NEW_OUTPUT_DIRECTORY
```

Supply the actual `go version -m` text recorded for that binary; the packager
checks it against the executable's embedded metadata. The source ref must equal
the checkout's full `HEAD`, with no tracked changes. Untracked CI output files
are excluded by the committed source archive. A fresh output directory is
required; existing archives are never overwritten.

```sh
python3 tools/verify-policy-impact-kit.py \
  --archive NEW_OUTPUT_DIRECTORY/policy-impact-linux-amd64.zip \
  --source-ref FULL_COMMIT --output NEW_VERIFICATION_JSON
```

Default verification inspects the ZIP, source bytes, metadata and new packaging
failure cases without invoking the product. `--run-demo` additionally extracts
into a fresh directory and runs this same four-call demo once on the matching
host. It records actual summaries, reports, permission checks and retained-byte
digests. This is distribution-workflow evidence, not a rerun of the closed
native regression corpora. Existing output paths are refused.
