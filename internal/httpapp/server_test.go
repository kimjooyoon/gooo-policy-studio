package httpapp

import (
	"bytes"
	"encoding/json"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const validInput = `{"request":{"key":"R1","requester":"alice","team":"product","amount":750000,"submitted":true},"reviewer":{"key":"bob","team":"product","active":true},"before":{"limit":500000,"same_team":true,"active_reviewer":true,"prevent_self":true},"after":{"limit":1000000,"same_team":true,"active_reviewer":true,"prevent_self":true}}`

func call(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	return w
}
func TestSimulateAndReplay(t *testing.T) {
	w := call("POST", "/api/simulate", validInput)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var r policy.Receipt
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Result.After.Approved || r.Result.Before.Approved {
		t.Fatal(r.Result)
	}
	b, _ := json.Marshal(r)
	w = call("POST", "/api/replay", string(b))
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"matched":true`)) {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestRejectMalformed(t *testing.T) {
	for _, body := range []string{`{}`, strings.Replace(validInput, `"submitted":true`, `"submitted":null`, 1), strings.Replace(validInput, `"amount":750000`, `"amount":1.5`, 1), strings.Replace(validInput, `"amount":750000`, `"amount":-1`, 1), strings.Replace(validInput, `"amount":750000`, `"amount":750000,"amount":0`, 1), strings.Replace(validInput, `"key":"R1",`, ``, 1), strings.Replace(validInput, `"key":"R1"`, `"unknown":"R1"`, 1), validInput + `{}`, strings.Repeat("x", 129<<10)} {
		w := call("POST", "/api/simulate", body)
		if w.Code < 400 {
			t.Fatalf("accepted %s", body[:min(len(body), 80)])
		}
	}
}
func TestOriginAndStaticFiles(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/simulate", strings.NewReader(validInput))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://elsewhere.example")
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/source"} {
		w = call("GET", path, "")
		if w.Code != http.StatusOK || w.Header().Get("Content-Security-Policy") == "" {
			t.Fatal(path, w.Code)
		}
	}
	if call("GET", "/private", "").Code != 404 {
		t.Fatal("unexpected static path")
	}
	r = httptest.NewRequest("POST", "/api/simulate", strings.NewReader(validInput))
	w = httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
}
