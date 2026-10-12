package httpapp

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
)

func impactFixture(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("../../examples/automation-policy/impact-input.json")
	if err != nil {
		t.Fatal(err)
	}
	var in policy.BatchInput
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	corpus, _ := json.Marshal(struct {
		Cases []policy.Case `json:"cases"`
	}{in.Cases})
	return string(raw), string(corpus)
}

func TestImpactAPIWholeReportReplayAndFailure(t *testing.T) {
	raw, corpus := impactFixture(t)
	if w := call("POST", "/api/impact/corpus", corpus); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := call("POST", "/api/impact", raw)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var report policy.BatchReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Checks.Passed || len(report.Rows) != 5 {
		t.Fatal("incomplete report")
	}
	if checked := call("POST", "/api/impact/check", raw); checked.Code != 200 {
		t.Fatal("matching automation check failed", checked.Code)
	}
	w = call("POST", "/api/impact/replay", w.Body.String())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"matched":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	// Successful transport cannot convert a requirement mismatch to PASS.
	raw = strings.Replace(raw, `"limit": 1000000`, `"limit": 500000`, 1)
	w = call("POST", "/api/impact", raw)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Checks.Passed || report.Checks.Mismatched != 1 || len(report.Rows) != 5 {
		t.Fatal("requirement mismatch lost")
	}
	checked := call("POST", "/api/impact/check", raw)
	if checked.Code != 409 {
		t.Fatal("mismatched automation check returned success", checked.Code)
	}
	if err := json.Unmarshal(checked.Body.Bytes(), &report); err != nil || report.Checks.Passed || len(report.Rows) != 5 {
		t.Fatal("automation failure did not preserve the complete report", err)
	}
}

func TestImpactAPIRejectsInvalidLastCaseAndCaps(t *testing.T) {
	raw, corpus := impactFixture(t)
	for name, body := range map[string]string{
		"last null":  strings.Replace(corpus, `"reason":"SELF_APPROVAL"`, `"reason":null`, 1),
		"case alias": strings.Replace(corpus, `"amount":750000`, `"amount":750000,"Amount":0`, 1),
		"duplicate":  strings.Replace(corpus, `"amount":750000`, `"amount":750000,"amount":0`, 1),
		"null case":  `{"cases":[null]}`,
		"invalid id": strings.Replace(corpus, `api-self-review-005`, `invalid id`, 1),
	} {
		if w := call("POST", "/api/impact/corpus", body); w.Code < 400 {
			t.Fatalf("%s admitted", name)
		}
	}
	var doc map[string]json.RawMessage
	json.Unmarshal([]byte(corpus), &doc)
	var cases []map[string]json.RawMessage
	json.Unmarshal(doc["cases"], &cases)
	delete(cases[len(cases)-1], "expected_after")
	doc["cases"], _ = json.Marshal(cases)
	bad, _ := json.Marshal(doc)
	if w := call("POST", "/api/impact/corpus", string(bad)); w.Code != 400 {
		t.Fatal("missing last expectation admitted", w.Code)
	}
	for path, limit := range map[string]int{"/api/impact/corpus": 256 << 10, "/api/impact": 1 << 20, "/api/impact/replay": 4 << 20} {
		if w := call("POST", path, strings.Repeat(" ", limit)+raw); w.Code != 413 {
			t.Fatal(path, "size cap", w.Code)
		}
	}
}
