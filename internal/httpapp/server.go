package httpapp

import (
	"encoding/json"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
	"github.com/kimjooyoon/gooo-policy-studio/web"
	"io"
	"net/http"
	"strings"
)

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/source", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"gooo": policy.Source, "go": policy.Generated, "generation": policy.Generation})
	})
	mux.HandleFunc("POST /api/simulate", func(w http.ResponseWriter, r *http.Request) {
		var in policy.Input
		if !decode(w, r, &in) {
			return
		}
		out, err := policy.Simulate(in)
		if err != nil {
			write(w, 422, map[string]string{"error": err.Error()})
			return
		}
		write(w, 200, out)
	})
	mux.HandleFunc("POST /api/replay", func(w http.ResponseWriter, r *http.Request) {
		var in policy.Receipt
		if !decode(w, r, &in) {
			return
		}
		out, err := policy.Replay(in)
		if err != nil {
			write(w, 422, map[string]string{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"matched": true, "receipt": out})
	})
	mux.HandleFunc("POST /api/impact/corpus", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Cases []policy.Case `json:"cases"`
		}
		if !decodeLimit(w, r, &in, 256<<10) {
			return
		}
		// Corpus admission validates every case before any domain activity runs.
		if err := policy.ValidateBatch(policy.BatchInput{Schema: policy.BatchInputSchema, Label: "corpus admission", Cases: in.Cases}); err != nil {
			write(w, 422, map[string]string{"error": err.Error()})
			return
		}
		write(w, 200, in)
	})
	impact := func(w http.ResponseWriter, r *http.Request) {
		var in policy.BatchInput
		if !decodeLimit(w, r, &in, 1<<20) {
			return
		}
		out, err := policy.SimulateBatch(in)
		if err != nil {
			write(w, 422, map[string]string{"error": err.Error()})
			return
		}
		status := http.StatusOK
		if r.URL.Path == "/api/impact/check" && !out.Checks.Passed {
			status = http.StatusConflict
		}
		write(w, status, out)
	}
	mux.HandleFunc("POST /api/impact", impact)
	// This route is suitable for automation: a mismatch cannot be a 2xx
	// successful check, while the complete failed report remains inspectable.
	mux.HandleFunc("POST /api/impact/check", impact)
	mux.HandleFunc("POST /api/impact/replay", func(w http.ResponseWriter, r *http.Request) {
		var in policy.BatchReport
		if !decodeLimit(w, r, &in, 4<<20) {
			return
		}
		out, err := policy.ReplayBatch(in)
		if err != nil {
			write(w, 422, map[string]string{"error": err.Error()})
			return
		}
		write(w, 200, map[string]any{"matched": true, "report": out})
	})
	files := http.FileServerFS(web.Files)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		// Same-origin browser requests only. No cookies, accounts or server persistence.
		if r.Method == "POST" {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				write(w, 403, map[string]string{"error": "같은 출처의 요청만 허용합니다"})
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				scheme := "http"
				if r.TLS != nil {
					scheme = "https"
				}
				if origin != scheme+"://"+r.Host {
					write(w, 403, map[string]string{"error": "출처가 일치하지 않습니다"})
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	return decodeLimit(w, r, out, 128<<10)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, out any, maxBytes int64) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		write(w, 415, map[string]string{"error": "application/json이 필요합니다"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		write(w, 413, map[string]string{"error": "JSON 입력의 크기 제한을 초과했거나 본문을 읽을 수 없습니다"})
		return false
	}
	if err := jsoninput.Decode(raw, out, int(maxBytes)); err != nil {
		write(w, 400, map[string]string{"error": "JSON 입력을 확인하세요: " + err.Error()})
		return false
	}
	return true
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
