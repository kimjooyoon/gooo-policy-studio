//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package admission

// These expectations were authored from the frozen artifact-preflight contract
// and public type declarations before inspecting the implementation bodies.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kimjooyoon/gooo-policy-studio/internal/artifactpreflight"
	"github.com/kimjooyoon/gooo-policy-studio/internal/machinerules"
)

func artifactFixture(t *testing.T, claims int) (Bootstrap, []byte, time.Time) {
	t.Helper()
	moment := time.Now().UTC().Truncate(time.Second)
	b := fixtureBootstrap()
	b.Schema = BootstrapSchemaV2
	b.Requests = b.Requests[:1]
	fields := claims
	if fields > 255 {
		fields = 255
	}
	recipe := artifactpreflight.Recipe{Schema: artifactpreflight.RecipeSchema, ProducerID: artifactpreflight.ProducerID,
		ArtifactSchema: "policy-studio/integration-artifact/v1", MaxBytes: artifactpreflight.MaxBytes,
		Fields: []artifactpreflight.Field{}, Claims: []artifactpreflight.Claim{}}
	values := map[string]any{"schema": recipe.ArtifactSchema}
	for i := 0; i < fields; i++ {
		name := fmt.Sprintf("field%03d", i)
		recipe.Fields = append(recipe.Fields, artifactpreflight.Field{Name: name, Type: "text"})
		values[name] = "allow"
	}
	for i := 0; i < claims; i++ {
		recipe.Claims = append(recipe.Claims, artifactpreflight.Claim{ID: fmt.Sprintf("Claim%03d", i),
			Verifier: artifactpreflight.VerifierID, Field: fmt.Sprintf("field%03d", i%fields), Expected: "allow"})
	}
	approval := machinerules.EffectBudget{AllowTarget: true, AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}
	control := machinerules.EffectBudget{AllowSession: true, AllowFilesystem: true, RequireIdempotent: true}
	b.Preflight = &ArtifactPolicy{Schema: ArtifactPolicySchema, ID: "IntegrationPolicy", Revision: 1, Recipe: recipe,
		RequiredAuthority: "live-observation", MaxAgeSeconds: 10, ApprovalBudget: approval, ControlPlaneBudget: control}
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	artifactDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(artifactDir, "artifact.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	b.Artifacts = []ArtifactRequirement{{RequestID: b.Requests[0].Key, Path: path,
		ExpectedSHA256: fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), DeadlineUnix: moment.Unix() + 3600}}
	return b, raw, moment
}

func artifactStore(t *testing.T, b Bootstrap, moment time.Time) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := Init(dir, b); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return moment }
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func replaceArtifactBytes(t *testing.T, b *Bootstrap, raw []byte, bind bool) {
	t.Helper()
	if err := os.WriteFile(b.Artifacts[0].Path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if bind {
		b.Artifacts[0].ExpectedSHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	}
}

func assertArtifactDenial(t *testing.T, s *Store, result Result, err error) {
	t.Helper()
	requireCode(t, err, PolicyDenied)
	if result.Outcome.Committed || result.Outcome.Preflight == nil || result.Outcome.Preflight.Decision.Admitted ||
		result.Outcome.PriorRevision != 1 || result.Outcome.NewRevision != 1 || s.state.Requests[0].Status != Pending ||
		s.state.Requests[0].Revision != 1 || len(s.state.Outcomes) != 1 {
		t.Fatal("artifact denial did not retain one result without approving the request")
	}
}

func TestArtifactGateVariableClaimsPreserveEveryOutcome(t *testing.T) {
	for _, count := range []int{1, 5, 256} {
		indexes := []int{-1, 0}
		if count > 1 {
			indexes = append(indexes, count/2, count-1)
		}
		for _, failIndex := range indexes {
			t.Run(fmt.Sprintf("claims-%d-failure-%d", count, failIndex), func(t *testing.T) {
				b, raw, moment := artifactFixture(t, count)
				if failIndex >= 0 {
					b.Preflight.Recipe.Claims[failIndex].Expected = "deny"
				}
				s, dir := artifactStore(t, b, moment)
				c := commandFor(t, s, b.Requests[0].Key, "all-claims")
				result, err := s.Admit(fixtureToken, c)
				if failIndex >= 0 {
					assertArtifactDenial(t, s, result, err)
				} else if err != nil || !result.Outcome.Committed || result.Outcome.Schema != OutcomeSchemaV2 {
					t.Fatalf("actual valid artifact was not approved: %v", err)
				}
				report := result.Outcome.Preflight
				if report == nil || len(report.Producer.Observations) != count || len(report.Evidence) != count ||
					len(report.Completion.Steps) != count || len(report.Completion.Input.Records) != count ||
					report.Completion.Summary.Total != int64(count) || report.Completion.Coverage.RequiredCount != int64(count) ||
					report.Completion.Coverage.MatchedCount != int64(count) {
					t.Fatal("variable recipe omitted observations or did not fold the full ordered claim corpus")
				}
				retained, err := base64.StdEncoding.DecodeString(report.Producer.ArtifactBase64)
				if err != nil || !bytes.Equal(retained, raw) || report.Producer.ActualSHA256 != b.Artifacts[0].ExpectedSHA256 ||
					!report.Producer.DigestOK || !report.Producer.SchemaOK || !report.Producer.TypesOK {
					t.Fatal("report does not bind the actual retained artifact bytes")
				}
				for i, observation := range report.Producer.Observations {
					want := "pass"
					if i == failIndex {
						want = "fail"
					}
					if observation.ClaimID != b.Preflight.Recipe.Claims[i].ID || observation.Status != want ||
						report.Completion.Input.Records[i].Status != want || report.Completion.Steps[i].Index != int64(i) ||
						report.Evidence[i].ClaimID != observation.ClaimID || report.Evidence[i].Decision.Admissible != (want == "pass") {
						t.Fatalf("observation %d lost its literal expected outcome", i)
					}
				}
				wantFail := int64(0)
				if failIndex >= 0 {
					wantFail = 1
				}
				if report.Completion.Summary.Fail != wantFail || report.Completion.Summary.Pass != int64(count)-wantFail ||
					report.Completion.Readiness.Ready != (failIndex < 0) || report.Decision.Admitted != (failIndex < 0) {
					t.Fatal("a later success erased a failure or final readiness disagreed with actual outcomes")
				}
				original := cloneValue(result.Outcome)
				s = reopenStore(t, s, dir)
				again, againErr := s.Admit(fixtureToken, c)
				if failIndex >= 0 {
					requireCode(t, againErr, PolicyDenied)
				} else if againErr != nil {
					t.Fatal(againErr)
				}
				if !again.Replayed || !reflect.DeepEqual(again.Outcome, original) {
					t.Fatal("restart did not reproduce the exact durable artifact result")
				}
			})
		}
	}
}

func TestArtifactGateMandatoryIntegrityAndTypedPredicates(t *testing.T) {
	variants := map[string]struct {
		raw  string
		bind bool
	}{
		"changed-digest":  {`{"schema":"policy-studio/integration-artifact/v1","field000":"changed"}`, false},
		"wrong-schema":    {`{"schema":"another/schema","field000":"allow"}`, true},
		"wrong-type":      {`{"schema":"policy-studio/integration-artifact/v1","field000":true}`, true},
		"wrong-value":     {`{"schema":"policy-studio/integration-artifact/v1","field000":"deny"}`, true},
		"extra-field":     {`{"schema":"policy-studio/integration-artifact/v1","field000":"allow","extra":"ignored"}`, true},
		"missing-field":   {`{"schema":"policy-studio/integration-artifact/v1"}`, true},
		"duplicate-field": {`{"schema":"policy-studio/integration-artifact/v1","field000":"deny","field000":"allow"}`, true},
		"case-alias":      {`{"schema":"policy-studio/integration-artifact/v1","Field000":"allow"}`, true},
		"null":            {`{"schema":"policy-studio/integration-artifact/v1","field000":null}`, true},
		"surrogate":       {`{"schema":"policy-studio/integration-artifact/v1","field000":"\ud800"}`, true},
		"multiple-json":   {`{"schema":"policy-studio/integration-artifact/v1","field000":"allow"}{}`, true},
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 1)
			if variant.bind {
				replaceArtifactBytes(t, &b, []byte(variant.raw), true)
			}
			s, _ := artifactStore(t, b, moment)
			if !variant.bind {
				replaceArtifactBytes(t, &b, []byte(variant.raw), false)
			}
			result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, name))
			assertArtifactDenial(t, s, result, err)
			if result.Outcome.Preflight.Completion.Readiness.Ready || result.Outcome.Preflight.Evidence[0].Decision.Admissible {
				t.Fatal("mandatory integrity or the exact typed predicate was bypassed by a one-claim recipe")
			}
		})
	}
	for _, kind := range []string{"bool", "int64"} {
		t.Run("typed-"+kind, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 1)
			b.Preflight.Recipe.Fields[0].Type = kind
			value := "true"
			if kind == "int64" {
				value = "9007199254740993"
			}
			b.Preflight.Recipe.Claims[0].Expected = value
			raw := []byte(`{"schema":"policy-studio/integration-artifact/v1","field000":` + value + `}`)
			replaceArtifactBytes(t, &b, raw, true)
			s, _ := artifactStore(t, b, moment)
			result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, kind))
			if err != nil || !result.Outcome.Committed || result.Outcome.Preflight.Producer.Observations[0].Actual != value {
				t.Fatalf("typed value lost its exact meaning: %v", err)
			}
		})
	}
}

func TestArtifactGateReadFailureAndOversizedContentDeny(t *testing.T) {
	for _, variant := range []string{"missing", "oversized"} {
		t.Run(variant, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			s, _ := artifactStore(t, b, moment)
			if variant == "missing" {
				if err := os.Remove(b.Artifacts[0].Path); err != nil {
					t.Fatal(err)
				}
			} else {
				replaceArtifactBytes(t, &b, bytes.Repeat([]byte("x"), int(artifactpreflight.MaxBytes)+1), false)
			}
			result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, variant))
			assertArtifactDenial(t, s, result, err)
			for _, observation := range result.Outcome.Preflight.Producer.Observations {
				if observation.Status == "pass" {
					t.Fatal("failed acquisition generated a passing claim")
				}
			}
		})
	}
}

func TestArtifactGateConfigurationAndControlPlaneBudgetRejectBeforeCreation(t *testing.T) {
	mutations := map[string]func(*Bootstrap){
		"no-preflight":       func(b *Bootstrap) { b.Preflight = nil },
		"v1-with-v2":         func(b *Bootstrap) { b.Schema = BootstrapSchema },
		"no-artifact":        func(b *Bootstrap) { b.Artifacts = nil },
		"wrong-request":      func(b *Bootstrap) { b.Artifacts[0].RequestID = "missing" },
		"duplicate-artifact": func(b *Bootstrap) { b.Artifacts = append(b.Artifacts, b.Artifacts[0]) },
		"relative-path":      func(b *Bootstrap) { b.Artifacts[0].Path = "artifact.json" },
		"zero-deadline":      func(b *Bootstrap) { b.Artifacts[0].DeadlineUnix = 0 },
		"unknown-producer":   func(b *Bootstrap) { b.Preflight.Recipe.ProducerID = "remote-unverified/v1" },
		"unknown-verifier":   func(b *Bootstrap) { b.Preflight.Recipe.Claims[0].Verifier = "trust_caller/v1" },
		// Unsupported authority fails initialization; the live file reader
		// cannot manufacture native-ABI evidence.
		"unsupported-authority": func(b *Bootstrap) { b.Preflight.RequiredAuthority = "native-abi" },
		"empty-claims":          func(b *Bootstrap) { b.Preflight.Recipe.Claims = nil },
		"duplicate-claims": func(b *Bootstrap) {
			b.Preflight.Recipe.Claims = append(b.Preflight.Recipe.Claims, b.Preflight.Recipe.Claims[0])
		},
		"negative-age":          func(b *Bootstrap) { b.Preflight.MaxAgeSeconds = -1 },
		"excessive-age":         func(b *Bootstrap) { b.Preflight.MaxAgeSeconds = 86401 },
		"no-control-filesystem": func(b *Bootstrap) { b.Preflight.ControlPlaneBudget.AllowFilesystem = false },
		"no-control-session":    func(b *Bootstrap) { b.Preflight.ControlPlaneBudget.AllowSession = false },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b, _, _ := artifactFixture(t, 1)
			mutate(&b)
			dir := filepath.Join(t.TempDir(), "never-created")
			requireCode(t, Init(dir, b), InvalidInput)
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid administrative configuration created durable state")
			}
		})
	}
}

func TestArtifactGateApprovalBudgetDenialAndAuthorityAreDurable(t *testing.T) {
	for _, variant := range []string{"target", "base-policy"} {
		t.Run(variant, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			switch variant {
			case "target":
				b.Preflight.ApprovalBudget.AllowTarget = false
			case "base-policy":
				b.Policy.Limit = 1
			}
			s, dir := artifactStore(t, b, moment)
			c := commandFor(t, s, b.Requests[0].Key, variant)
			result, err := s.Admit(fixtureToken, c)
			assertArtifactDenial(t, s, result, err)
			p := result.Outcome.Preflight
			if !p.ControlPlaneEffects.Admissible {
				t.Fatal("denial used an unapproved control-plane effect")
			}
			if variant == "target" && (p.ApprovalEffects.Admissible || p.ApprovalEffects.TargetOK) {
				t.Fatal("target prohibition was ignored")
			}
			if variant == "base-policy" && p.Decision.BasePolicyOK {
				t.Fatal("artifact checks bypassed the base policy")
			}
			s = reopenStore(t, s, dir)
			again, err := s.Admit(fixtureToken, c)
			requireCode(t, err, PolicyDenied)
			if !again.Replayed || !reflect.DeepEqual(result.Outcome, again.Outcome) {
				t.Fatal("restart changed durable denial")
			}
		})
	}
}

func TestArtifactGateBasePolicyDenialDoesNotAcquirePrivateContent(t *testing.T) {
	b, _, moment := artifactFixture(t, 5)
	b.Requests[0].Team = "private-other-team"
	s, _ := artifactStore(t, b, moment)
	// A valid readable file exists. A request-domain authorization denial must
	// occur without acquiring it, rather than only suppressing its output later.
	result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, "no-private-read"))
	assertArtifactDenial(t, s, result, err)
	p := result.Outcome.Preflight
	if p.Decision.BasePolicyOK || p.Producer.AcquisitionStatus != artifactpreflight.Skipped || p.Producer.ArtifactBase64 != "" || p.Producer.ByteCount != 0 {
		t.Fatal("base-policy denied principal acquired or retained private artifact content")
	}
	if len(p.Producer.Observations) != 5 || len(p.Completion.Steps) != 5 || p.Completion.Readiness.Ready {
		t.Fatal("skipped private acquisition omitted required non-pass observations")
	}
	for _, observation := range p.Producer.Observations {
		if observation.Status != "unknown" {
			t.Fatal("unobserved private artifact was labeled as verified")
		}
	}
}

func TestArtifactGateFreshnessRecheckedAfterPreparedWrite(t *testing.T) {
	for _, limit := range []string{"age", "deadline"} {
		t.Run(limit, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			b.Preflight.MaxAgeSeconds = 2
			if limit == "deadline" {
				b.Artifacts[0].DeadlineUnix = moment.Unix() + 1
			}
			s, dir := artifactStore(t, b, moment)
			current := moment
			s.now = func() time.Time { return current }
			write := s.operations.write
			writes := 0
			s.operations.write = func(file *os.File, raw []byte) (int, error) {
				writes++
				n, err := write(file, raw)
				if writes == 1 {
					current = moment.Add(3 * time.Second)
				}
				return n, err
			}
			rename := s.operations.rename
			renames := 0
			s.operations.rename = func(old, next string) error { renames++; return rename(old, next) }
			result, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, limit))
			assertArtifactDenial(t, s, result, err)
			if writes != 2 || renames != 1 || result.Outcome.Preflight.DecisionUnix != current.Unix() {
				t.Fatal("expired temporary approval was renamed or denial was not recomputed and durably saved")
			}
			if limit == "age" && result.Outcome.Preflight.Evidence[0].Decision.FreshnessOK {
				t.Fatal("stale evidence was authorized")
			}
			if limit == "deadline" && result.Outcome.Preflight.Evidence[0].Decision.DeadlineOK {
				t.Fatal("expired request was authorized")
			}
			s = reopenStore(t, s, dir)
			if s.state.Requests[0].Status != Pending || len(s.state.Outcomes) != 1 || s.state.Outcomes[0].Committed {
				t.Fatal("expired approval survived restart")
			}
		})
	}
}

func TestArtifactGateHistoricalRetryDoesNotReauthorizeOrReadMutablePath(t *testing.T) {
	b, _, moment := artifactFixture(t, 5)
	b.Artifacts[0].DeadlineUnix = moment.Unix() + 1
	s, dir := artifactStore(t, b, moment)
	c := commandFor(t, s, b.Requests[0].Key, "once")
	first, err := s.Admit(fixtureToken, c)
	if err != nil || !first.Outcome.Committed {
		t.Fatal("initial actual artifact was not admitted", err)
	}
	if err := os.WriteFile(b.Artifacts[0].Path, []byte("invalid replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	s = reopenStore(t, s, dir)
	s.now = func() time.Time { return moment.Add(365 * 24 * time.Hour) }
	again, err := s.Admit(fixtureToken, c)
	if err != nil || !again.Replayed || !reflect.DeepEqual(first.Outcome, again.Outcome) || len(s.state.Outcomes) != 1 {
		t.Fatal("historical retry reran mutable path or current expiry checks", err)
	}
	changed := c
	changed.RequestID = "other"
	_, err = s.Admit(fixtureToken, changed)
	requireCode(t, err, Conflict)
	for _, token := range []string{strings.Repeat("c", 64), strings.Repeat("d", 64)} {
		result, err := s.Admit(token, c)
		want := Forbidden
		if token == strings.Repeat("c", 64) {
			want = Unauthorized
		}
		requireCode(t, err, want)
		if result.Outcome.ID != "" {
			t.Fatal("unauthorized historical access disclosed a report")
		}
	}
}

func TestArtifactGateContextSupportsOriginalIDsAndOwnsNestedResults(t *testing.T) {
	b, _, moment := artifactFixture(t, 5)
	b.Requests[0].Key = "자동화:요청-" + strings.Repeat("x", 80)
	b.Artifacts[0].RequestID = b.Requests[0].Key
	s, dir := artifactStore(t, b, moment)
	b.Preflight.Recipe.Claims[0].Expected = "externally-mutated"
	view, err := s.Inspect(fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	view.Requests[0].Request.Amount = 9_000_000_000
	c := commandFor(t, s, b.Requests[0].Key, "owned")
	result, err := s.Admit(fixtureToken, c)
	if err != nil || !result.Outcome.Committed {
		t.Fatal("caller mutation changed trusted configuration", err)
	}
	p := result.Outcome.Preflight
	if p.Context.Request.Request.Key != b.Requests[0].Key || p.Completion.Input.RequestID != "req_"+strings.TrimPrefix(p.ContextSHA256, "sha256:") {
		t.Fatal("completion identity lost the original authoritative request binding")
	}
	original := cloneValue(result.Outcome)
	p.Producer.Observations[0].Status = "fail"
	p.Completion.Policy.RequiredClaims[0] = "Changed"
	p.Completion.Input.Records[0].EvidenceIDs[0] = "ev_" + strings.Repeat("0", 64)
	p.Evidence[0].Facts.ProviderVerified = false
	p.Context.Implementation.Machine.Sources[0].SHA256 = "sha256:" + strings.Repeat("0", 64)
	again, err := s.Admit(fixtureToken, c)
	if err != nil || !reflect.DeepEqual(again.Outcome, original) {
		t.Fatal("returned nested data mutated trusted history", err)
	}
	s = reopenStore(t, s, dir)
	again, err = s.Admit(fixtureToken, c)
	if err != nil || !reflect.DeepEqual(again.Outcome, original) {
		t.Fatal("trusted nested history was not durably owned", err)
	}
}

func TestArtifactGateConcurrentCommandsHaveOneTransition(t *testing.T) {
	b, _, moment := artifactFixture(t, 5)
	s, _ := artifactStore(t, b, moment)
	command := commandFor(t, s, b.Requests[0].Key, "race")
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			c := command
			c.IdempotencyKey = fmt.Sprintf("racer-%d", i)
			_, err := s.Admit(fixtureToken, c)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	approved, conflicts := 0, 0
	for err := range results {
		if err == nil {
			approved++
		} else {
			requireCode(t, err, Conflict)
			conflicts++
		}
	}
	if approved != 1 || conflicts != 15 || len(s.state.Outcomes) != 1 || s.state.Requests[0].Revision != 2 {
		t.Fatal("concurrent commands committed multiple local effects")
	}
}

func TestArtifactGateRehashedHistoryTamperingCannotPassReplay(t *testing.T) {
	mutations := map[string]func(*snapshot){
		"host-code":            func(s *snapshot) { s.Implementation.HostSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"producer-code":        func(s *snapshot) { s.Implementation.Producer.VerifierSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"recipe":               func(s *snapshot) { s.Preflight.Recipe.Claims[0].Expected = "deny" },
		"budget":               func(s *snapshot) { s.Preflight.ApprovalBudget.AllowTarget = false },
		"artifact-requirement": func(s *snapshot) { s.Artifacts[0].ExpectedSHA256 = "sha256:" + strings.Repeat("0", 64) },
		"context-request":      func(s *snapshot) { s.Outcomes[0].Preflight.Context.Request.Request.Amount++ },
		"context-principal":    func(s *snapshot) { s.Outcomes[0].Preflight.Context.Principal.Key = "svc-peer" },
		"retained-bytes": func(s *snapshot) {
			s.Outcomes[0].Preflight.Producer.ArtifactBase64 = base64.StdEncoding.EncodeToString([]byte("changed"))
		},
		"producer-status":  func(s *snapshot) { s.Outcomes[0].Preflight.Producer.Observations[0].Status = "fail" },
		"evidence-facts":   func(s *snapshot) { s.Outcomes[0].Preflight.Evidence[0].Facts.ProviderVerified = false },
		"evidence-result":  func(s *snapshot) { s.Outcomes[0].Preflight.Evidence[0].Decision.Admissible = false },
		"completion-step":  func(s *snapshot) { s.Outcomes[0].Preflight.Completion.Steps[0].Decision.Pass++ },
		"completion-claim": func(s *snapshot) { s.Outcomes[0].Preflight.Completion.Policy.RequiredClaims[0] = "Unrequired" },
		"audit":            func(s *snapshot) { s.Outcomes[0].Preflight.Audit.Approval.AccessesNetwork = true },
		"final-result":     func(s *snapshot) { s.Outcomes[0].Preflight.Decision.Admitted = false },
		"recorded-time":    func(s *snapshot) { s.Outcomes[0].Preflight.DecisionUnix += 7200 },
		"malformed-created-at": func(s *snapshot) {
			out := &s.Outcomes[0]
			out.CreatedAt, out.Receipt.CreatedAt = "not-a-time", "not-a-time"
			out.Receipt.ID = ""
			raw, err := json.Marshal(out.Receipt)
			if err != nil {
				panic(err)
			}
			out.Receipt.ID = digest(raw)
		},
		"missing-preflight": func(s *snapshot) { s.Outcomes[0].Preflight = nil },
		"schema-downgrade":  func(s *snapshot) { s.Schema = snapshotSchema },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			s, dir := artifactStore(t, b, moment)
			if _, err := s.Admit(fixtureToken, commandFor(t, s, b.Requests[0].Key, "original")); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			saved := savedSnapshot(t, dir)
			mutate(&saved)
			for i := range saved.Outcomes {
				saved.Outcomes[i].ID = outcomeID(saved.Outcomes[i])
			}
			replaceSnapshot(t, dir, saved)
			opened, err := Open(dir)
			if err == nil {
				_ = opened.Close()
				t.Fatal("rehashed inconsistent history passed current source/config/result reconstruction")
			}
			requireCode(t, err, Unavailable)
		})
	}
}

func TestArtifactGatePredictableByteCapacityRejectsWithoutWriteOrFailStop(t *testing.T) {
	b, _, moment := artifactFixture(t, 5)
	s, dir := artifactStore(t, b, moment)
	path := filepath.Join(dir, snapshotName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.byteLimit = len(before) + 1
	writes := 0
	write := s.operations.write
	s.operations.write = func(file *os.File, raw []byte) (int, error) { writes++; return write(file, raw) }
	c := commandFor(t, s, b.Requests[0].Key, "capacity")
	_, err = s.Admit(fixtureToken, c)
	requireCode(t, err, Unavailable)
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || writes != 0 || s.failed || len(s.state.Outcomes) != 0 || s.state.Requests[0].Status != Pending {
		t.Fatal("predictable byte-capacity rejection wrote, evicted, transitioned or poisoned the store")
	}
	if _, err := s.Inspect(fixtureToken); err != nil {
		t.Fatal("byte capacity disabled inspection", err)
	}
	s.byteLimit = 0
	result, err := s.Admit(fixtureToken, c)
	if err != nil || !result.Outcome.Committed || writes != 1 {
		t.Fatal("unchanged command could not proceed after restoring the test cap", err)
	}
	again, err := s.Admit(fixtureToken, c)
	if err != nil || !again.Replayed || writes != 1 {
		t.Fatal("capacity recovery lost idempotent history", err)
	}
}

func TestArtifactGatePersistenceFaultRecoveryRetainsCompleteOutcome(t *testing.T) {
	for _, stage := range []string{"write", "short-write", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			s, dir := artifactStore(t, b, moment)
			c := commandFor(t, s, b.Requests[0].Key, "recover-same-key")
			switch stage {
			case "write":
				s.operations.write = func(*os.File, []byte) (int, error) { return 0, io.ErrClosedPipe }
			case "short-write":
				s.operations.write = func(f *os.File, raw []byte) (int, error) { return f.Write(raw[:len(raw)/2]) }
			case "rename":
				s.operations.rename = func(string, string) error { return errors.New("injected rename fault") }
			case "directory-sync":
				s.operations.syncDirectory = func(string) error { return errors.New("injected sync fault") }
			}
			result, err := s.Admit(fixtureToken, c)
			requireCode(t, err, Unavailable)
			if result.Outcome.ID != "" || !s.failed {
				t.Fatal("I/O uncertainty exposed a definitive result or remained available")
			}
			s = reopenStore(t, s, dir)
			s.now = func() time.Time { return moment }
			result, err = s.Admit(fixtureToken, c)
			if err != nil || !result.Outcome.Committed || result.Outcome.Preflight == nil || result.Replayed != (stage == "directory-sync") || len(s.state.Outcomes) != 1 {
				t.Fatal("same-key recovery lost a complete artifact-bound transition", err)
			}
		})
	}
}

func TestArtifactGateTimingBoundaryAndClockRollback(t *testing.T) {
	for _, variant := range []string{"deadline-equality", "zero-age-same-second", "zero-age-after-write", "backwards-after-write"} {
		t.Run(variant, func(t *testing.T) {
			b, _, moment := artifactFixture(t, 5)
			b.Preflight.MaxAgeSeconds = 0
			if variant == "deadline-equality" {
				b.Artifacts[0].DeadlineUnix = moment.Unix()
			}
			if variant == "backwards-after-write" {
				second := b.Requests[0]
				second.Key = "second-pending"
				b.Requests = append(b.Requests, second)
				requirement := b.Artifacts[0]
				requirement.RequestID = second.Key
				b.Artifacts = append(b.Artifacts, requirement)
			}
			s, dir := artifactStore(t, b, moment)
			var historical Result
			var historicalCommand Command
			requestID := b.Requests[0].Key
			if variant == "backwards-after-write" {
				historicalCommand = commandFor(t, s, requestID, "prior-history")
				var err error
				historical, err = s.Admit(fixtureToken, historicalCommand)
				if err != nil || !historical.Outcome.Committed {
					t.Fatal("could not establish prior valid history", err)
				}
				requestID = b.Requests[1].Key
			}
			before, err := os.ReadFile(filepath.Join(dir, snapshotName))
			if err != nil {
				t.Fatal(err)
			}
			current := moment
			s.now = func() time.Time { return current }
			write := s.operations.write
			writes := 0
			s.operations.write = func(file *os.File, raw []byte) (int, error) {
				writes++
				n, err := write(file, raw)
				if writes == 1 {
					if variant == "zero-age-after-write" {
						current = moment.Add(time.Second)
					}
					if variant == "backwards-after-write" {
						current = moment.Add(-time.Second)
					}
				}
				return n, err
			}
			rename := s.operations.rename
			renames := 0
			s.operations.rename = func(old, next string) error { renames++; return rename(old, next) }
			command := commandFor(t, s, requestID, variant)
			result, err := s.Admit(fixtureToken, command)
			switch variant {
			case "deadline-equality":
				assertArtifactDenial(t, s, result, err)
				if result.Outcome.Preflight.Evidence[0].Decision.DeadlineOK || writes != 1 || renames != 1 {
					t.Fatal("deadline equality was treated as a live authorization")
				}
			case "zero-age-same-second":
				if err != nil || !result.Outcome.Committed || !result.Outcome.Preflight.Evidence[0].Decision.FreshnessOK || writes != 1 || renames != 1 {
					t.Fatal("zero-age same-second observation did not admit exactly one transition", err)
				}
			case "zero-age-after-write":
				assertArtifactDenial(t, s, result, err)
				if result.Outcome.Preflight.Evidence[0].Decision.FreshnessOK || writes != 2 || renames != 1 {
					t.Fatal("zero-age precommit freshness was not rechecked")
				}
			case "backwards-after-write":
				requireCode(t, err, Unavailable)
				after, readErr := os.ReadFile(filepath.Join(dir, snapshotName))
				if readErr != nil || !bytes.Equal(before, after) || result.Outcome.ID != "" || s.failed || writes != 1 || renames != 0 || len(s.state.Outcomes) != 1 || s.state.Requests[1].Status != Pending {
					t.Fatal("backwards precommit clock renamed, changed history, or poisoned the store")
				}
				if _, err := s.Inspect(fixtureToken); err != nil {
					t.Fatal("rollback discarded readable prior history", err)
				}
				again, err := s.Admit(fixtureToken, historicalCommand)
				if err != nil || !again.Replayed || !reflect.DeepEqual(again.Outcome, historical.Outcome) || writes != 1 {
					t.Fatal("rollback lost the original durable idempotent result", err)
				}
				current = moment
				result, err = s.Admit(fixtureToken, command)
				if err != nil || !result.Outcome.Committed || writes != 2 || renames != 1 || len(s.state.Outcomes) != 2 {
					t.Fatal("known pre-rename rollback prevented a safe same-key retry", err)
				}
			}
		})
	}
}
