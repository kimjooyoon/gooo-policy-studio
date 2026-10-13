package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactimpact"
)

const usage = `policy-impact compares two proposed v2 artifact policies locally.

Usage:
  policy-impact compare --case FILE --before FILE --after FILE --report NEW_FILE

First use (from a source checkout with the existing Go toolchain):
  go build -o policy-impact ./cmd/policy-impact
  # Prepare private 0600 copies following examples/artifact-impact/README.md.
  ./policy-impact compare --case private/case.json --before private/policy-internal.json --after private/policy-external.json --report private/comparison.json
  # Reverse --before and --after with a new --report to compare the other direction.

Inputs are bounded 0600 regular files. The case selects an absolute artifact
path and trusted expected SHA/deadline. The required report is a new synced
0600 file and contains private facts and retained bytes. stdout is a safe
summary. No server, token, network, admission commit or target action is used.
Exit 0 means the comparison report was saved, including denied decisions.
Exit 2 means a fixed configuration, file or host failure; a reserved empty or
partial report may remain. Existing reports are never overwritten.
`

func run(args []string, out io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprint(out, usage)
		return 0
	}
	emit := func(s artifactimpact.Summary, exit int) int {
		if json.NewEncoder(out).Encode(s) != nil {
			return 2
		}
		return exit
	}
	if len(args) == 0 || args[0] != "compare" {
		return emit(artifactimpact.Failure("USAGE_INVALID"), 2)
	}
	flags := flag.NewFlagSet("compare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var paths artifactimpact.Paths
	seen := map[string]bool{}
	for _, field := range []struct {
		name   string
		target *string
	}{{"case", &paths.Case}, {"before", &paths.Before}, {"after", &paths.After}, {"report", &paths.Report}} {
		flags.Func(field.name, "private file", func(value string) error {
			if seen[field.name] {
				return errors.New("repeated flag")
			}
			seen[field.name] = true
			*field.target = value
			return nil
		})
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprint(out, usage)
			return 0
		}
		return emit(artifactimpact.Failure("USAGE_INVALID"), 2)
	}
	if flags.NArg() != 0 || paths.Case == "" || paths.Before == "" || paths.After == "" || paths.Report == "" {
		return emit(artifactimpact.Failure("USAGE_INVALID"), 2)
	}
	summary, exit := artifactimpact.CompareFiles(paths)
	return emit(summary, exit)
}

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }
