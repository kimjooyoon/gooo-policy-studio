package policy

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func fixture() Input {
	return Input{Request: Request{"REQ-1", "alice", "product", 750000, true}, Reviewer: Reviewer{"bob", "product", true}, Before: Rules{500000, true, true, true}, After: Rules{1000000, true, true, true}}
}
func TestGoooDomainDecisions(t *testing.T) {
	tests := []struct {
		name          string
		mutate        func(*Input)
		before, after string
		direction     string
	}{
		{"limit change", func(*Input) {}, "OVER_LIMIT", "APPROVED", "NEWLY_APPROVED"},
		{"exact limit", func(i *Input) { i.Request.Amount = 500000 }, "APPROVED", "APPROVED", "UNCHANGED"},
		{"limit plus one", func(i *Input) { i.Request.Amount = 1000001 }, "OVER_LIMIT", "OVER_LIMIT", "UNCHANGED"},
		{"zero", func(i *Input) { i.Request.Amount = 0 }, "APPROVED", "APPROVED", "UNCHANGED"},
		{"inactive", func(i *Input) { i.Reviewer.Active = false }, "REVIEWER_INACTIVE", "REVIEWER_INACTIVE", "UNCHANGED"},
		{"inactive relaxed", func(i *Input) { i.Reviewer.Active = false; i.After.ActiveReviewer = false }, "REVIEWER_INACTIVE", "APPROVED", "NEWLY_APPROVED"},
		{"team", func(i *Input) { i.Reviewer.Team = "ops" }, "TEAM_MISMATCH", "TEAM_MISMATCH", "UNCHANGED"},
		{"team relaxed", func(i *Input) { i.Reviewer.Team = "ops"; i.After.SameTeam = false }, "TEAM_MISMATCH", "APPROVED", "NEWLY_APPROVED"},
		{"self", func(i *Input) { i.Reviewer.Key = i.Request.Requester }, "SELF_APPROVAL", "SELF_APPROVAL", "UNCHANGED"},
		{"self relaxed", func(i *Input) { i.Reviewer.Key = i.Request.Requester; i.After.PreventSelf = false }, "SELF_APPROVAL", "APPROVED", "NEWLY_APPROVED"},
		{"draft priority", func(i *Input) { i.Request.Submitted = false; i.Reviewer.Active = false }, "NOT_SUBMITTED", "NOT_SUBMITTED", "UNCHANGED"},
		{"stricter", func(i *Input) { i.Before.Limit = 1000000; i.After.Limit = 500000 }, "APPROVED", "OVER_LIMIT", "NEWLY_DENIED"},
		{"reason change", func(i *Input) { i.Reviewer.Active = false; i.After.ActiveReviewer = false; i.After.Limit = 500000 }, "REVIEWER_INACTIVE", "OVER_LIMIT", "UNCHANGED"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := fixture()
			tc.mutate(&i)
			r, err := Simulate(i)
			if err != nil {
				t.Fatal(err)
			}
			if r.Result.Before.Reason != tc.before || r.Result.After.Reason != tc.after || r.Result.Change.Direction != tc.direction {
				t.Fatalf("unexpected %+v", r.Result)
			}
			if tc.name == "reason change" && !r.Result.Change.ReasonChanged {
				t.Fatal("reason change lost")
			}
		})
	}
}
func TestDecisionTruthTable(t *testing.T) {
	// Independent oracle covers all five boolean condition combinations, exact limit
	// and over-limit inputs, and all eight configurable policy switch combinations.
	for mask := 0; mask < 32; mask++ {
		for switches := 0; switches < 8; switches++ {
			i := fixture()
			submitted := mask&1 != 0
			active := mask&2 != 0
			differentPerson := mask&4 != 0
			sameTeam := mask&8 != 0
			withinLimit := mask&16 != 0
			i.Request.Submitted = submitted
			i.Reviewer.Active = active
			if !differentPerson {
				i.Reviewer.Key = i.Request.Requester
			}
			if !sameTeam {
				i.Reviewer.Team = "other"
			}
			i.Request.Amount = 500000
			if !withinLimit {
				i.Request.Amount = 500001
			}
			i.Before = Rules{500000, switches&1 != 0, switches&2 != 0, switches&4 != 0}
			i.After = i.Before
			r, err := Simulate(i)
			if err != nil {
				t.Fatal(err)
			}
			want := submitted && (!i.Before.ActiveReviewer || active) && (!i.Before.PreventSelf || differentPerson) && (!i.Before.SameTeam || sameTeam) && withinLimit
			if r.Result.Before.Approved != want || r.Result.Change.Changed {
				t.Fatalf("mask %d switches %d: %+v", mask, switches, r.Result)
			}
		}
	}
}
func TestReceiptReplayAndTamper(t *testing.T) {
	r, err := Simulate(fixture())
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := Replay(r)
	if err != nil || !reflect.DeepEqual(r.Result, fresh.Result) {
		t.Fatal(err)
	}
	r.Input.Request.Amount++
	if _, err := Replay(r); err == nil {
		t.Fatal("tampered input accepted")
	}
	r.Result.After.Approved = !r.Result.After.Approved
	r.ID = receiptID(r)
	if _, err := Replay(r); err == nil {
		t.Fatal("modified result accepted")
	}
	r, _ = Simulate(fixture())
	r.SourceDigest = "sha256:stale"
	r.ID = receiptID(r)
	if _, err := Replay(r); err == nil {
		t.Fatal("stale source accepted")
	}
}
func TestInputBounds(t *testing.T) {
	for _, n := range []int64{-1, MaxAmount + 1} {
		i := fixture()
		i.Request.Amount = n
		if _, err := Simulate(i); err == nil {
			t.Fatal("invalid amount accepted")
		}
	}
	i := fixture()
	i.Request.Team = " "
	if _, err := Simulate(i); err == nil {
		t.Fatal("empty team accepted")
	}
}
func TestSourceAndGeneratedBindings(t *testing.T) {
	var gen struct {
		Source    string `json:"source_sha256"`
		Generated string `json:"generated_sha256"`
		Adapter   string `json:"adapter_sha256"`
	}
	if err := json.Unmarshal(Generation, &gen); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct{ path, embedded, digest string }{{"../../policy/approval.gooo", Source, gen.Source}, {"rules_generated.go", Generated, gen.Generated}} {
		b, err := os.ReadFile(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != check.embedded || hash(b) != check.digest {
			t.Fatalf("binding mismatch %s", check.path)
		}
	}
	b, err := os.ReadFile("bridge_generated.go")
	if err != nil || hash(b) != gen.Adapter {
		t.Fatal("bridge digest mismatch", err)
	}
	b, err = os.ReadFile("../../evidence/generation.json")
	if err != nil || string(b) != string(Generation) {
		t.Fatal("evidence copy mismatch", err)
	}
}
