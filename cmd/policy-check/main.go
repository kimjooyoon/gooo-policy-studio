// policy-check runs finite requirements against compiled Gooo decisions.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

const maxInputBytes = 1 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// Exit 0 is a finite match, 1 a complete report containing mismatches, and 2
// an invalid input or execution error. No network or external action is taken.
func run(args []string, input io.Reader, output, diagnostics io.Writer) int {
	flags := flag.NewFlagSet("policy-check", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("input", "-", "impact input JSON file, or - for stdin")
	replay := flags.Bool("replay", false, "replay an exported impact report")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *path != "-" {
		file, err := os.Open(*path)
		if err != nil {
			fmt.Fprintln(diagnostics, err)
			return 2
		}
		defer file.Close()
		input = file
	}
	limit := maxInputBytes
	if *replay {
		limit = 4 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
	if err != nil || len(raw) > limit {
		fmt.Fprintln(diagnostics, "입력의 바이트 제한을 초과했거나 읽을 수 없습니다")
		return 2
	}
	var report policy.BatchReport
	if *replay {
		var saved policy.BatchReport
		err = jsoninput.Decode(raw, &saved, limit)
		if err == nil {
			report, err = policy.ReplayBatch(saved)
		}
	} else {
		var in policy.BatchInput
		err = jsoninput.Decode(raw, &in, limit)
		if err == nil {
			report, err = policy.SimulateBatch(in)
		}
	}
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	if !report.Checks.Passed {
		return 1
	}
	return 0
}
