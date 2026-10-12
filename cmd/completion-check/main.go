// completion-check runs compiled Gooo completion rules over supplied outcomes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kimjooyoon/gooo-policy-studio/internal/completion"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// Exit 0 means ready, 1 is a complete not-ready report, and 2 means invalid
// input/configuration/replay or an execution/output error. No effect is granted.
func run(args []string, input io.Reader, output, diagnostics io.Writer) int {
	flags := flag.NewFlagSet("completion-check", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	policyPath := flags.String("policy", "", "required operator-selected completion policy file")
	inputPath := flags.String("input", "-", "input JSON file, or - for stdin")
	replay := flags.Bool("replay", false, "recompute and verify an exported completion report")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *policyPath == "" || *policyPath == "-" {
		fmt.Fprintln(diagnostics, "--policy must select a local policy file")
		return 2
	}
	policyFile, err := os.Open(*policyPath)
	if err != nil {
		fmt.Fprintln(diagnostics, "cannot open completion policy:", err)
		return 2
	}
	defer policyFile.Close()
	rawPolicy, err := readLimited(policyFile, completion.MaxPolicyBytes)
	if err != nil {
		fmt.Fprintln(diagnostics, "policy:", err)
		return 2
	}
	policy, policyDigest, err := completion.DecodePolicy(rawPolicy)
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	if *inputPath != "-" {
		file, err := os.Open(*inputPath)
		if err != nil {
			fmt.Fprintln(diagnostics, "cannot open completion input:", err)
			return 2
		}
		defer file.Close()
		input = file
	}
	limit := completion.MaxInputBytes
	if *replay {
		limit = completion.MaxReplayBytes
	}
	rawInput, err := readLimited(input, limit)
	if err != nil {
		fmt.Fprintln(diagnostics, "input:", err)
		return 2
	}
	var report completion.Report
	if *replay {
		var saved completion.Report
		err = jsoninput.Decode(rawInput, &saved, limit)
		if err == nil {
			report, err = completion.Replay(policy, policyDigest, saved)
		}
	} else {
		var request completion.Input
		err = jsoninput.Decode(rawInput, &request, limit)
		if err == nil {
			report, err = completion.Evaluate(policy, request, policyDigest)
		}
	}
	if err != nil {
		fmt.Fprintln(diagnostics, err)
		return 2
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(diagnostics, "cannot write completion report:", err)
		return 2
	}
	if !report.Readiness.Ready {
		return 1
	}
	return 0
}

func readLimited(input io.Reader, limit int) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read JSON: %w", err)
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, fmt.Errorf("JSON must be 1..%d bytes", limit)
	}
	return raw, nil
}
