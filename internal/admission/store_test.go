//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

var fixtureToken = strings.Repeat("a", 64)

func fixtureBootstrap() Bootstrap {
	return Bootstrap{Schema: BootstrapSchema,
		Policy: policy.Rules{Limit: 1_000_000, SameTeam: true, ActiveReviewer: true, PreventSelf: true},
		Principals: []Principal{
			{Key: "svc-policy-engine", Team: "platform", Active: true, Enabled: true, CanExecute: true, TokenSHA256: TokenDigest(fixtureToken)},
			{Key: "svc-peer", Team: "platform", Active: true, Enabled: true, CanExecute: true, TokenSHA256: TokenDigest(strings.Repeat("b", 64))},
			{Key: "svc-disabled", Team: "platform", Active: true, Enabled: false, CanExecute: true, TokenSHA256: TokenDigest(strings.Repeat("c", 64))},
			{Key: "svc-inspector", Team: "platform", Active: true, Enabled: true, CanExecute: false, TokenSHA256: TokenDigest(strings.Repeat("d", 64))},
			{Key: "svc-inactive", Team: "platform", Active: false, Enabled: true, CanExecute: true, TokenSHA256: TokenDigest(strings.Repeat("e", 64))},
		},
		Requests: []policy.Request{
			{Key: "api-allowed", Requester: "svc-client", Team: "platform", Amount: 750_000, Submitted: true},
			{Key: "api-denied", Requester: "svc-client", Team: "platform", Amount: 1_100_000, Submitted: true},
		}}
}

func initializedStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := Init(dir, fixtureBootstrap()); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func commandFor(t *testing.T, s *Store, request, key string) Command {
	t.Helper()
	v, err := s.Inspect(fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	return Command{RequestID: request, ExpectedRevision: 1, PolicyVersion: v.PolicyVersion, IdempotencyKey: key}
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var gateError *Error
	if !errors.As(err, &gateError) || gateError.Code != want {
		t.Fatalf("expected error code %s, got %v", want, err)
	}
}

func reopenStore(t *testing.T, s *Store, dir string) *Store {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = next.Close() })
	return next
}

func savedSnapshot(t *testing.T, dir string) snapshot {
	t.Helper()
	saved, err := readSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func replaceSnapshot(t *testing.T, dir string, saved snapshot) {
	t.Helper()
	saved.ID = snapshotID(saved)
	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotName), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialPermissionAndServerBindings(t *testing.T) {
	s, dir := initializedStore(t)
	c := commandFor(t, s, "api-allowed", "command-1")
	for _, token := range []string{"", strings.Repeat("z", 64), strings.Repeat("c", 64)} {
		_, err := s.Inspect(token)
		requireCode(t, err, Unauthorized)
		_, err = s.Admit(token, c)
		requireCode(t, err, Unauthorized)
	}
	_, err := s.Admit(strings.Repeat("d", 64), c)
	requireCode(t, err, Forbidden)
	view, err := s.Inspect(fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	if bytes.Contains(raw, []byte("token_sha256")) || bytes.Contains(raw, []byte("svc-peer")) || bytes.Contains(raw, []byte(fixtureToken)) {
		t.Fatal("view disclosed a credential or another principal")
	}
	view.Requests[0].Request.Amount = 0
	badCommands := []struct {
		name    string
		command Command
		code    string
	}{
		{"stale-policy", Command{c.RequestID, 1, "sha256:" + strings.Repeat("0", 64), "stale-policy"}, Conflict},
		{"stale-revision", Command{c.RequestID, 2, c.PolicyVersion, "stale-revision"}, Conflict},
		{"unknown-request", Command{"missing", 1, c.PolicyVersion, "missing"}, Conflict},
		{"invalid-revision", Command{c.RequestID, 0, c.PolicyVersion, "invalid-revision"}, InvalidInput},
		{"invalid-policy", Command{c.RequestID, 1, "current", "invalid-policy"}, InvalidInput},
		{"invalid-idempotency", Command{c.RequestID, 1, c.PolicyVersion, " key"}, InvalidInput},
	}
	for _, test := range badCommands {
		t.Run(test.name, func(t *testing.T) { _, err := s.Admit(fixtureToken, test.command); requireCode(t, err, test.code) })
	}
	if len(s.state.Outcomes) != 0 || s.state.Requests[0].Revision != 1 {
		t.Fatal("pre-execution rejection changed state")
	}
	result, err := s.Admit(fixtureToken, c)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || !result.Outcome.Committed || result.Outcome.PriorRevision != 1 || result.Outcome.NewRevision != 2 || result.Outcome.Command != c {
		t.Fatal("approval outcome binding is wrong")
	}
	in := result.Outcome.Receipt.Input
	if in.Request != fixtureBootstrap().Requests[0] || in.Reviewer != (policy.Reviewer{Key: "svc-policy-engine", Team: "platform", Active: true}) || in.Before != fixtureBootstrap().Policy || in.After != in.Before {
		t.Fatal("compiled Gooo did not receive only authoritative server values")
	}
	view, err = s.Inspect(fixtureToken)
	if err != nil || view.Requests[0].Status != Approved || view.Requests[0].Revision != 2 {
		t.Fatal("approval transition is absent")
	}
	for _, path := range []string{dir, filepath.Join(dir, snapshotName), filepath.Join(dir, lockName)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if path == dir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("state or credential-bearing file is not owner-only")
		}
	}
	private, err := os.ReadFile(filepath.Join(dir, snapshotName))
	if err != nil || bytes.Contains(private, []byte(fixtureToken)) {
		t.Fatal("plaintext credential appeared in state")
	}
}

func TestDurableApprovalAndDenialIdempotency(t *testing.T) {
	s, dir := initializedStore(t)
	approve := commandFor(t, s, "api-allowed", "allow-once")
	deny := commandFor(t, s, "api-denied", "deny-once")
	allowed, err := s.Admit(fixtureToken, approve)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := s.Admit(fixtureToken, deny)
	requireCode(t, err, PolicyDenied)
	if denied.Outcome.Committed || denied.Outcome.Receipt.Result.After.Reason != "OVER_LIMIT" || denied.Outcome.PriorRevision != 1 || denied.Outcome.NewRevision != 1 || len(s.state.Outcomes) != 2 {
		t.Fatal("denial must retain its actual decision without changing request state")
	}
	s = reopenStore(t, s, dir)
	again, err := s.Admit(fixtureToken, approve)
	if err != nil || !again.Replayed || again.Outcome != allowed.Outcome {
		t.Fatal("restart changed the original approval outcome")
	}
	again, err = s.Admit(fixtureToken, deny)
	requireCode(t, err, PolicyDenied)
	if !again.Replayed || again.Outcome != denied.Outcome {
		t.Fatal("restart changed the original denial outcome")
	}
	changed := approve
	changed.RequestID = "api-denied"
	_, err = s.Admit(fixtureToken, changed)
	requireCode(t, err, Conflict)
	// The same key is independently scoped to each authenticated principal.
	peerDenied, err := s.Admit(strings.Repeat("b", 64), deny)
	requireCode(t, err, PolicyDenied)
	if peerDenied.Replayed || peerDenied.Outcome.PrincipalKey != "svc-peer" {
		t.Fatal("idempotency crossed principal boundaries")
	}
	_, err = s.Admit(strings.Repeat("e", 64), Command{"api-denied", 1, deny.PolicyVersion, "inactive"})
	requireCode(t, err, PolicyDenied)
	if s.state.Outcomes[len(s.state.Outcomes)-1].Receipt.Result.After.Reason != "REVIEWER_INACTIVE" {
		t.Fatal("active is a Gooo reviewer condition, not credential enablement")
	}
}

func TestRevocationPrecedesHistoricalOutcomeAccess(t *testing.T) {
	for _, permission := range []string{"enabled", "can_execute"} {
		t.Run(permission, func(t *testing.T) {
			s, dir := initializedStore(t)
			c := commandFor(t, s, "api-allowed", "original")
			if _, err := s.Admit(fixtureToken, c); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			saved := savedSnapshot(t, dir)
			if permission == "enabled" {
				saved.Principals[0].Enabled = false
			} else {
				saved.Principals[0].CanExecute = false
			}
			replaceSnapshot(t, dir, saved)
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.Admit(fixtureToken, c)
			want := Forbidden
			if permission == "enabled" {
				want = Unauthorized
			}
			requireCode(t, err, want)
			if got != (Result{}) {
				t.Fatal("revoked principal read its historical outcome")
			}
		})
	}
}

func TestConcurrentDifferentKeysCommitOneApproval(t *testing.T) {
	s, _ := initializedStore(t)
	c := commandFor(t, s, "api-allowed", "race")
	const contenders = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	approvals, conflicts := 0, 0
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			command := c
			command.IdempotencyKey = fmt.Sprintf("race-%d", i)
			result, err := s.Admit(fixtureToken, command)
			mu.Lock()
			defer mu.Unlock()
			if err == nil && result.Outcome.Committed {
				approvals++
			} else {
				var e *Error
				if errors.As(err, &e) && e.Code == Conflict {
					conflicts++
				} else {
					t.Errorf("unexpected competing admission: %v", err)
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if approvals != 1 || conflicts != contenders-1 || len(s.state.Outcomes) != 1 || s.state.Requests[0].Revision != 2 {
		t.Fatal("concurrent commands did not serialize one local effect")
	}
}

func TestPersistenceFailureStopsFurtherEffectsAndRecovers(t *testing.T) {
	for _, stage := range []string{"write", "short-write", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			s, dir := initializedStore(t)
			c := commandFor(t, s, "api-allowed", "retry-the-same-key")
			switch stage {
			case "write":
				s.operations.write = func(*os.File, []byte) (int, error) { return 0, io.ErrClosedPipe }
			case "short-write":
				s.operations.write = func(f *os.File, raw []byte) (int, error) { return f.Write(raw[:len(raw)/2]) }
			case "rename":
				s.operations.rename = func(string, string) error { return errors.New("injected rename failure") }
			case "directory-sync":
				s.operations.syncDirectory = func(string) error { return errors.New("injected post-rename sync failure") }
			}
			result, err := s.Admit(fixtureToken, c)
			requireCode(t, err, Unavailable)
			if result != (Result{}) || !s.failed {
				t.Fatal("failed persistence exposed a definitive outcome or retained availability")
			}
			_, err = s.Inspect(fixtureToken)
			requireCode(t, err, Unavailable)
			_, err = s.Admit(fixtureToken, c)
			requireCode(t, err, Unavailable)
			s = reopenStore(t, s, dir)
			if stage == "directory-sync" {
				if len(s.state.Outcomes) != 1 || s.state.Requests[0].Status != Approved {
					t.Fatal("post-rename recovery lost the complete durable candidate")
				}
				result, err = s.Admit(fixtureToken, c)
				if err != nil || !result.Replayed || !result.Outcome.Committed {
					t.Fatal("ambiguous I/O retry did not recover the original outcome")
				}
			} else {
				if len(s.state.Outcomes) != 0 || s.state.Requests[0].Status != Pending {
					t.Fatal("pre-rename failure changed the authoritative snapshot")
				}
				result, err = s.Admit(fixtureToken, c)
				if err != nil || result.Replayed || !result.Outcome.Committed {
					t.Fatal("clean recovery could not commit the same command")
				}
			}
			leftovers, err := filepath.Glob(filepath.Join(dir, ".snapshot-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatal("temporary credential-bearing snapshot was retained")
			}
		})
	}
}

func TestLifetimeLockAndInitNeverReplace(t *testing.T) {
	s, dir := initializedStore(t)
	if second, err := Open(dir); err == nil {
		second.Close()
		t.Fatal("two live stores acquired the same state")
	} else {
		requireCode(t, err, Unavailable)
	}
	before, err := os.ReadFile(filepath.Join(dir, snapshotName))
	if err != nil {
		t.Fatal(err)
	}
	requireCode(t, Init(dir, fixtureBootstrap()), Conflict)
	after, err := os.ReadFile(filepath.Join(dir, snapshotName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("initialization replaced existing state")
	}
	empty := filepath.Join(t.TempDir(), "already-exists")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	requireCode(t, Init(empty, fixtureBootstrap()), Conflict)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestAdmissionLockHelper$")
	child.Env = append(os.Environ(), "GOOO_ADMISSION_TEST_LOCK_DIR="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("second process obtained ownership or failed unexpectedly: %v %s", err, output)
	}
	s = reopenStore(t, s, dir)
	if _, err := s.Inspect(fixtureToken); err != nil {
		t.Fatal("lifetime lock was not released")
	}
}

func TestAdmissionLockHelper(t *testing.T) {
	dir := os.Getenv("GOOO_ADMISSION_TEST_LOCK_DIR")
	if dir == "" {
		return
	}
	store, err := Open(dir)
	if err == nil {
		store.Close()
		os.Exit(2)
	}
	var gateError *Error
	if !errors.As(err, &gateError) || gateError.Code != Unavailable {
		os.Exit(3)
	}
}

func TestBootstrapBoundsAndExactInventory(t *testing.T) {
	tests := map[string]func(*Bootstrap){
		"unknown-schema":       func(b *Bootstrap) { b.Schema = "other" },
		"no-principal":         func(b *Bootstrap) { b.Principals = nil },
		"too-many-principals":  func(b *Bootstrap) { b.Principals = make([]Principal, MaxPrincipals+1) },
		"too-many-requests":    func(b *Bootstrap) { b.Requests = make([]policy.Request, MaxRequests+1) },
		"duplicate-principal":  func(b *Bootstrap) { b.Principals[1].Key = b.Principals[0].Key },
		"duplicate-credential": func(b *Bootstrap) { b.Principals[1].TokenSHA256 = b.Principals[0].TokenSHA256 },
		"invalid-credential":   func(b *Bootstrap) { b.Principals[0].TokenSHA256 = "SHA256:invalid" },
		"blank-team":           func(b *Bootstrap) { b.Principals[0].Team = "  " },
		"control-principal":    func(b *Bootstrap) { b.Principals[0].Key = "svc\nother" },
		"duplicate-request":    func(b *Bootstrap) { b.Requests[1].Key = b.Requests[0].Key },
		"invalid-utf8":         func(b *Bootstrap) { b.Requests[0].Key = string([]byte{0xff}) },
		"over-budget-bound":    func(b *Bootstrap) { b.Requests[0].Amount = policy.MaxAmount + 1 },
		"negative-limit":       func(b *Bootstrap) { b.Policy.Limit = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			b := fixtureBootstrap()
			mutate(&b)
			requireCode(t, ValidateBootstrap(b), InvalidInput)
			dir := filepath.Join(t.TempDir(), "invalid-state")
			requireCode(t, Init(dir, b), InvalidInput)
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid bootstrap created state")
			}
		})
	}
	b := fixtureBootstrap()
	b.Principals = make([]Principal, MaxPrincipals)
	for i := range b.Principals {
		b.Principals[i] = Principal{Key: fmt.Sprintf("svc-%d", i), Team: "platform", Enabled: true, TokenSHA256: TokenDigest(fmt.Sprintf("%064d", i))}
	}
	b.Requests = make([]policy.Request, MaxRequests)
	for i := range b.Requests {
		b.Requests[i] = policy.Request{Key: fmt.Sprintf("req-%d", i), Requester: "client", Team: "platform", Amount: policy.MaxAmount}
	}
	b.Policy.Limit = policy.MaxAmount
	if err := ValidateBootstrap(b); err != nil {
		t.Fatal("valid maximum inventory rejected", err)
	}
}

func TestDurableOutcomeCapacityNeverEvicts(t *testing.T) {
	s, dir := initializedStore(t)
	first := commandFor(t, s, "api-denied", "denied-0")
	var original Result
	for i := 0; i < MaxOutcomes; i++ {
		c := first
		c.IdempotencyKey = fmt.Sprintf("denied-%d", i)
		result, err := s.Admit(fixtureToken, c)
		requireCode(t, err, PolicyDenied)
		if i == 0 {
			original = result
		}
	}
	full := first
	full.IdempotencyKey = "capacity-exhausted"
	_, err := s.Admit(fixtureToken, full)
	requireCode(t, err, Unavailable)
	if s.failed || len(s.state.Outcomes) != MaxOutcomes {
		t.Fatal("capacity rejection changed state or hid prior outcomes")
	}
	s = reopenStore(t, s, dir)
	got, err := s.Admit(fixtureToken, first)
	requireCode(t, err, PolicyDenied)
	if !got.Replayed || got.Outcome != original.Outcome {
		t.Fatal("capacity evicted an original idempotent result")
	}
}

func TestRehashedSnapshotTamperingRejected(t *testing.T) {
	mutations := map[string]func(*snapshot){
		"policy-version":        func(s *snapshot) { s.PolicyVersion = "sha256:" + strings.Repeat("0", 64) },
		"source-binding":        func(s *snapshot) { s.Provenance.SourceDigest = "sha256:" + strings.Repeat("0", 64) },
		"generated-binding":     func(s *snapshot) { s.Provenance.GeneratedDigest = "sha256:" + strings.Repeat("0", 64) },
		"adapter-binding":       func(s *snapshot) { s.Provenance.AdapterDigest = "sha256:" + strings.Repeat("0", 64) },
		"generation-binding":    func(s *snapshot) { s.Provenance.GenerationDigest = "sha256:" + strings.Repeat("0", 64) },
		"compiler-binding":      func(s *snapshot) { s.Provenance.CompilerSource = strings.Repeat("0", 40) },
		"rules":                 func(s *snapshot) { s.Policy.Limit++; s.PolicyVersion = version(s.Policy, s.Provenance) },
		"authoritative-request": func(s *snapshot) { s.Requests[0].Request.Amount++ },
		"reviewer-team":         func(s *snapshot) { s.Principals[0].Team = "other" },
		"duplicate-credential":  func(s *snapshot) { s.Principals[1].TokenSHA256 = s.Principals[0].TokenSHA256 },
		"duplicate-request":     func(s *snapshot) { s.Requests = append(s.Requests, s.Requests[0]) },
		"missing-history":       func(s *snapshot) { s.Outcomes = []Outcome{} },
		"rollback-state":        func(s *snapshot) { s.Requests[0].Status, s.Requests[0].Revision = Pending, 1 },
		"duplicate-outcome":     func(s *snapshot) { s.Outcomes = append(s.Outcomes, s.Outcomes[0]) },
		"outcome-id":            func(s *snapshot) { s.Outcomes[0].ID = "sha256:" + strings.Repeat("0", 64) },
		"command-revision":      func(s *snapshot) { s.Outcomes[0].Command.ExpectedRevision = 2 },
		"prior-revision":        func(s *snapshot) { s.Outcomes[0].PriorRevision = 2 },
		"next-revision":         func(s *snapshot) { s.Outcomes[0].NewRevision = 3 },
		"principal-binding":     func(s *snapshot) { s.Outcomes[0].PrincipalKey = "svc-peer" },
		"committed-observation": func(s *snapshot) { s.Outcomes[0].Committed = false },
		"outcome-scope":         func(s *snapshot) { s.Outcomes[0].Scope = "immutable proof" },
		"actual-result": func(s *snapshot) {
			r := &s.Outcomes[0].Receipt
			r.Result.After.Reason = "OVER_LIMIT"
			r.ID = ""
			raw, _ := json.Marshal(*r)
			r.ID = digest(raw)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, dir := initializedStore(t)
			if _, err := s.Admit(fixtureToken, commandFor(t, s, "api-allowed", "approved")); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			saved := savedSnapshot(t, dir)
			mutate(&saved)
			// Rehash all valid inner outcome objects too: consistency/replay must
			// reject the mutation even when unkeyed content hashes are recomputed.
			if name != "outcome-id" {
				for i := range saved.Outcomes {
					saved.Outcomes[i].ID = outcomeID(saved.Outcomes[i])
				}
			}
			replaceSnapshot(t, dir, saved)
			opened, err := Open(dir)
			if err == nil {
				opened.Close()
				t.Fatal("rehashed inconsistent snapshot accepted")
			}
			requireCode(t, err, Unavailable)
		})
	}
}

func TestOriginalSnapshotJSONAndPermissionsRejected(t *testing.T) {
	for _, variant := range []string{"duplicate", "case-alias", "null", "missing", "unknown", "invalid-utf8", "mode", "symlink"} {
		t.Run(variant, func(t *testing.T) {
			s, dir := initializedStore(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, snapshotName)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"discarded","schema":`), 1)
			case "case-alias":
				raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1)
			case "null":
				raw = bytes.Replace(raw, []byte(`"outcomes":[]`), []byte(`"outcomes":null`), 1)
			case "missing":
				raw = bytes.Replace(raw, []byte(`,"outcomes":[]`), nil, 1)
			case "unknown":
				raw = append([]byte(`{"reviewer_override":true,`), raw[1:]...)
			case "invalid-utf8":
				raw = append(raw, 0xff)
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				backing := filepath.Join(dir, "renamed-snapshot")
				if err := os.Rename(path, backing); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(backing, path); err != nil {
					t.Fatal(err)
				}
			}
			if variant != "mode" && variant != "symlink" {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := Open(dir)
			if err == nil {
				opened.Close()
				t.Fatal("ambiguous or non-private original snapshot accepted")
			}
			requireCode(t, err, Unavailable)
		})
	}
}

func TestCurrentCodeEvidenceBinding(t *testing.T) {
	for _, evidence := range []string{"source", "generated", "generation"} {
		t.Run(evidence, func(t *testing.T) {
			s, dir := initializedStore(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			originalSource, originalGenerated := policy.Source, policy.Generated
			originalGeneration := append(json.RawMessage(nil), policy.Generation...)
			defer func() {
				policy.Source, policy.Generated, policy.Generation = originalSource, originalGenerated, originalGeneration
			}()
			switch evidence {
			case "source":
				policy.Source += "\n"
			case "generated":
				policy.Generated += "\n"
			case "generation":
				policy.Generation = append(append(json.RawMessage(nil), policy.Generation...), '\n')
			}
			opened, err := Open(dir)
			if err == nil {
				opened.Close()
				t.Fatal("changed current code/generation evidence accepted an old store")
			}
			requireCode(t, err, Unavailable)
		})
	}
}

func TestConsistentAdministratorRewriteIsNotAuthenticatedHistory(t *testing.T) {
	s, dir := initializedStore(t)
	if _, err := s.Admit(fixtureToken, commandFor(t, s, "api-allowed", "original")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	saved := savedSnapshot(t, dir)
	saved.Requests[0].Request.Amount = 50_000
	in := saved.Outcomes[0].Receipt.Input
	in.Request = saved.Requests[0].Request
	receipt, err := policy.Simulate(in)
	if err != nil {
		t.Fatal(err)
	}
	saved.Outcomes[0].Receipt, saved.Outcomes[0].CreatedAt = receipt, receipt.CreatedAt
	saved.Outcomes[0].ID = outcomeID(saved.Outcomes[0])
	replaceSnapshot(t, dir, saved)
	opened, err := Open(dir)
	if err != nil {
		t.Fatal("a fully consistent trusted local rewrite is outside unsigned history guarantees", err)
	}
	defer opened.Close()
	if opened.state.Outcomes[0].Receipt.Input.Request.Amount != 50_000 {
		t.Fatal("fixture rewrite did not apply")
	}
}
