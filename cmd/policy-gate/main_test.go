package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func TestInitializePrivateCredentialAndRefuseReplacement(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "bootstrap.json")
	tokenFile := filepath.Join(dir, "private", "access-token")
	state := filepath.Join(dir, "state")
	b := admission.Bootstrap{Schema: admission.BootstrapSchema, Policy: policy.Rules{Limit: 100}, Principals: []admission.Principal{{Key: "validator", Team: "platform", Active: true, Enabled: true, CanExecute: true}}, Requests: []policy.Request{{Key: "req", Requester: "client", Team: "platform", Amount: 50, Submitted: true}}}
	raw, _ := json.Marshal(b)
	if err := os.WriteFile(seed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-init", seed, "-state", state, "-token-file", tokenFile}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	credential, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(credential))
	if len(token) != 64 {
		t.Fatal("credential must contain 32 random bytes encoded as hex")
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tokenFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("credential file must be owner-only")
	}
	digest := sha256.Sum256([]byte(token))
	if strings.Contains(stdout.String()+stderr.String(), token) || strings.Contains(stdout.String(), hex.EncodeToString(digest[:])) {
		t.Fatal("credentials and their digests must not be printed")
	}
	store, err := admission.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inspect(token); err != nil {
		t.Fatal("generated credential does not authenticate initialized state")
	}
	_ = store.Close()
	if err := run([]string{"-init", seed, "-state", state, "-token-file", tokenFile}, &stdout, &stderr); err == nil {
		t.Fatal("repeat init must not replace private credential or trusted state")
	}
	after, _ := os.ReadFile(tokenFile)
	if !bytes.Equal(credential, after) {
		t.Fatal("existing credential changed")
	}
}

func TestInvalidBootstrapCreatesNoCredential(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "bad.json")
	token := filepath.Join(dir, "credential")
	if err := os.WriteFile(seed, []byte(`{"schema":"x","schema":"y"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"-init", seed, "-state", filepath.Join(dir, "state"), "-token-file", token}, &out, &out); err == nil {
		t.Fatal("ambiguous bootstrap accepted")
	}
	if _, err := os.Stat(token); !os.IsNotExist(err) {
		t.Fatal("invalid bootstrap created a credential")
	}
}

func TestRemoteListenersFailBeforeOpeningState(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8090", "192.0.2.1:8090", ":8090", "localhost:8090", "127.0.0.1:-1", "[::]:8090", "127.0.0.1:65536"} {
		if err := loopback(addr); err == nil {
			t.Fatalf("unsafe or ambiguous address accepted: %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:8090", "127.0.0.1:0", "[::1]:8090"} {
		if err := loopback(addr); err != nil {
			t.Fatalf("loopback rejected: %s", addr)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"-state", filepath.Join(t.TempDir(), "absent"), "-addr", "0.0.0.0:8090"}, &out, &out); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatal("remote address must fail before state access")
	}
}
