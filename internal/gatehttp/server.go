// Package gatehttp serves the bounded local machine request gate. It does not
// expose the simulation API or accept caller-defined policy or identity fields.
package gatehttp

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/kimjooyoon/gooo-policy-studio/internal/admission"
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
)

const MaxCommandBytes = 4 << 10

type Backend interface {
	Inspect(string) (admission.View, error)
	Admit(string, admission.Command) (admission.Result, error)
}

func Handler(store Backend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			writeError(w, admission.Unauthorized, nil)
			return
		}
		view, err := store.Inspect(token)
		if err != nil {
			backendError(w, err, nil)
			return
		}
		write(w, http.StatusOK, view)
	})
	mux.HandleFunc("POST /api/admit", func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer(r)
		if !ok {
			writeError(w, admission.Unauthorized, nil)
			return
		}
		// Authenticate before reading command contents. Admit checks the current
		// authority again inside the same critical section as the transition.
		if _, err := store.Inspect(token); err != nil {
			backendError(w, err, nil)
			return
		}
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
			write(w, http.StatusUnsupportedMediaType, map[string]string{"error": "CONTENT_TYPE_REQUIRED"})
			return
		}
		for k, v := range params {
			if k != "charset" || !strings.EqualFold(v, "utf-8") {
				write(w, http.StatusUnsupportedMediaType, map[string]string{"error": "UNSUPPORTED_CONTENT_TYPE_PARAMETER"})
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxCommandBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				write(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "COMMAND_TOO_LARGE"})
			} else {
				write(w, http.StatusBadRequest, map[string]string{"error": "COMMAND_READ_FAILED"})
			}
			return
		}
		var command admission.Command
		if err := jsoninput.Decode(raw, &command, MaxCommandBytes); err != nil {
			write(w, http.StatusBadRequest, map[string]string{"error": "INVALID_COMMAND_JSON"})
			return
		}
		if r.Context().Err() != nil {
			write(w, http.StatusRequestTimeout, map[string]string{"error": "REQUEST_CANCELLED"})
			return
		}
		out, err := store.Admit(token, command)
		if err != nil {
			backendError(w, err, &out)
			return
		}
		write(w, http.StatusOK, out)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// This separate listener is for authenticated machine clients. Browser
		// pages and URL credentials cannot grant a machine transition.
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" || r.URL.RawQuery != "" {
			write(w, http.StatusForbidden, map[string]string{"error": "MACHINE_CLIENT_REQUIRED"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) < 32 || len(parts[1]) > 256 {
		return "", false
	}
	for _, b := range []byte(parts[1]) {
		if b < 33 || b > 126 || b == ',' {
			return "", false
		}
	}
	return parts[1], true
}

func backendError(w http.ResponseWriter, err error, out *admission.Result) {
	var e *admission.Error
	if !errors.As(err, &e) {
		writeError(w, admission.Unavailable, nil)
		return
	}
	if e.Code != admission.PolicyDenied {
		out = nil
	}
	writeError(w, e.Code, out)
}

func writeError(w http.ResponseWriter, code string, out *admission.Result) {
	status := http.StatusServiceUnavailable
	switch code {
	case admission.Unauthorized:
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", "Bearer")
	case admission.Forbidden, admission.PolicyDenied:
		status = http.StatusForbidden
	case admission.InvalidInput:
		status = http.StatusUnprocessableEntity
	case admission.Conflict:
		status = http.StatusConflict
	}
	write(w, status, struct {
		Error  string            `json:"error"`
		Result *admission.Result `json:"result,omitempty"`
	}{code, out})
}

func write(w http.ResponseWriter, status int, out any) {
	// Encode before sending a success status. A disconnected response does not
	// undo a committed transition; its durable idempotency key enables retry.
	b, err := json.Marshal(out)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":"RESPONSE_ENCODING_FAILED"}`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n'))
}
