// policy-client prepares and submits one saved command to a local v2 gate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/kimjooyoon/gooo-policy-studio/internal/gateclient"
)

const usage = `policy-client: private-file client for the local v2 machine gate

Usage:
  policy-client prepare --server http://127.0.0.1:8091 --token-file <private0600file> --request-id <server-ownedID> --idempotency-key <explicitkey> --command-file <new0600file>
  policy-client submit --server http://127.0.0.1:8091 --token-file <private0600file> --command-file <existing0600file> [--report-file <new0600file>]
  policy-client --help

prepare performs one authenticated GET and exclusively saves a four-field command.
submit sends those unchanged saved bytes once, with no GET or automatic retry.
After uncertainty, explicitly submit the same command file to recover its original outcome.

New synthetic demo, from the repository root (build bin/policy-gate and bin/policy-client first):
  gooo_client_demo="$HOME/.local/state/gooo-policy-studio/client-demo"
  mkdir -m 700 -p "$HOME/.local/state/gooo-policy-studio"
  mkdir -m 700 "$gooo_client_demo"
  cp examples/gate-client/*.json "$gooo_client_demo/"
  ./bin/policy-gate -init "$gooo_client_demo/bootstrap.json" -state "$gooo_client_demo/state" -token-file "$gooo_client_demo/client.token"
  ./bin/policy-gate -state "$gooo_client_demo/state" -addr 127.0.0.1:8092
In another terminal, using the same demo directory:
  gooo_client_demo="$HOME/.local/state/gooo-policy-studio/client-demo"
  ./bin/policy-client prepare --server http://127.0.0.1:8092 --token-file "$gooo_client_demo/client.token" --request-id req-client-allow --idempotency-key client-allow-1 --command-file "$gooo_client_demo/allow.command.json"
  ./bin/policy-client submit --server http://127.0.0.1:8092 --token-file "$gooo_client_demo/client.token" --command-file "$gooo_client_demo/allow.command.json"
  ./bin/policy-client submit --server http://127.0.0.1:8092 --token-file "$gooo_client_demo/client.token" --command-file "$gooo_client_demo/allow.command.json"
Use a new demo directory; the last submit recovers the same original outcome.

Only literal loopback HTTP with an explicit port is supported; no proxy or redirect.
Requests have a fixed 10-second deadline. Token and command files must be regular,
non-symlink 0600 files. New command and report files are exclusive, 0600 and synced.
The optional report contains private artifact and predicate values; stdout is a safe summary.
Only v2 state and artifact-bound outcomes are supported. Approval is a local state transition.

Exit codes: 0 prepared or committed approval/replay; 1 durable policy denial/replay;
2 authentication, permission, conflict, unavailable, malformed, local I/O or transport uncertainty.
`

func main() { os.Exit(run(os.Args[1:], os.Stdout)) }

func run(args []string, out io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		if _, err := io.WriteString(out, usage); err != nil {
			return 2
		}
		return 0
	}
	if len(args) == 0 || args[0] != "prepare" && args[0] != "submit" {
		return emit(out, gateclient.LocalFailure("client", "USAGE_INVALID"))
	}
	action := args[0]
	fs := flag.NewFlagSet(action, flag.ContinueOnError)
	// Flag errors may contain supplied argument values. Never print them.
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "literal loopback HTTP endpoint")
	token := fs.String("token-file", "", "existing private 0600 token file")
	command := fs.String("command-file", "", "private command file")
	var request, key, report *string
	if action == "prepare" {
		request = fs.String("request-id", "", "server-owned pending request ID")
		key = fs.String("idempotency-key", "", "explicit stable operation key")
	} else {
		report = fs.String("report-file", "", "new private full response file")
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.WriteString(out, usage); err != nil {
				return 2
			}
			return 0
		}
		return emit(out, gateclient.LocalFailure(action, "USAGE_INVALID"))
	}
	if len(fs.Args()) != 0 || *server == "" || *token == "" || *command == "" {
		return emit(out, gateclient.LocalFailure(action, "USAGE_INVALID"))
	}
	if action == "prepare" {
		if *request == "" || *key == "" {
			return emit(out, gateclient.LocalFailure(action, "USAGE_INVALID"))
		}
		return emit(out, gateclient.Prepare(context.Background(), gateclient.PrepareOptions{Server: *server, TokenFile: *token, RequestID: *request, IdempotencyKey: *key, CommandFile: *command}))
	}
	return emit(out, gateclient.Submit(context.Background(), gateclient.SubmitOptions{Server: *server, TokenFile: *token, CommandFile: *command, ReportFile: *report}))
}

func emit(out io.Writer, result gateclient.Result) int {
	if json.NewEncoder(out).Encode(result.Summary) != nil {
		return 2
	}
	return result.ExitCode
}
