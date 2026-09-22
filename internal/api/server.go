package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bannerfp/internal/fingerprint"
)

const (
	maxBodyBytes   = 16 << 20
	maxBatchItems  = 5000
	maxBannerBytes = 256 << 10
)

type Server struct {
	engine *fingerprint.Engine
	log    *slog.Logger
}

func New(engine *fingerprint.Engine, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{engine: engine, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /fingerprint", s.fingerprint)
	return withRecover(s.log, withAccessLog(s.log, mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) fingerprint(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || raw[0] != '[' {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a json array"})
		return
	}

	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json array"})
		return
	}
	if len(items) > maxBatchItems {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many items"})
		return
	}

	inputs := make([]fingerprint.Input, 0, len(items))
	for _, item := range items {
		if item == nil {
			inputs = append(inputs, fingerprint.Input{})
			continue
		}
		banner := asString(item["banner"])
		if len(banner) > maxBannerBytes {
			banner = banner[:maxBannerBytes]
		}
		inputs = append(inputs, fingerprint.Input{
			IP:     asString(item["ip"]),
			Port:   asInt(item["port"]),
			Banner: banner,
		})
	}
	writeJSON(w, http.StatusOK, s.engine.IdentifyBatch(inputs))
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}

func asInt(v any) int {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return int(t)
	case json.Number:
		n, _ := t.Int64()
		return int(n)
	case int:
		return t
	case int64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func withRecover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic recovered", "err", rec, "path", r.URL.Path)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func withAccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		if r.URL.Path != "/health" {
			log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rw.status, "dur", time.Since(start).String())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
