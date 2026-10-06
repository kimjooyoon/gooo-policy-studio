package httpapp

import (
	"bytes"
	"encoding/json"
	"github.com/kimjooyoon/gooo-policy-studio/internal/policy"
	"github.com/kimjooyoon/gooo-policy-studio/web"
	"io"
	"net/http"
	"reflect"
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
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		write(w, 415, map[string]string{"error": "application/json이 필요합니다"})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	defer r.Body.Close()
	raw, err := io.ReadAll(r.Body)
	if err != nil || completeJSON(raw, reflect.TypeOf(out).Elem()) != nil {
		write(w, 400, map[string]string{"error": "필수 필드 누락·null·중복 키 또는 잘못된 JSON입니다"})
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		write(w, 400, map[string]string{"error": "JSON 형식·필드·정수 값을 확인하세요"})
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		write(w, 400, map[string]string{"error": "JSON 객체 하나만 입력하세요"})
		return false
	}
	return true
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
