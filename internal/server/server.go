// Package server exposes the banner recognition HTTP API.
package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/example/banner/internal/fingerprint"
	"github.com/example/banner/internal/models"
)

// Server wraps a recognition engine behind an HTTP handler.
type Server struct {
	engine *fingerprint.Engine
	mux    *http.ServeMux
}

// New returns a configured Server.
func New() *Server {
	s := &Server{
		engine: fingerprint.New(),
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("POST /fingerprint", s.handleFingerprint)
}

// Handler returns the underlying mux so callers can attach it to any http.Server.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	var req models.FingerprintRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid JSON body: " + err.Error(),
		})
		return
	}

	// Defensive cap to avoid pathological payloads.
	if len(req.Records) > 100000 {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": "too many records in a single request",
		})
		return
	}

	results := s.engine.RecognizeBatch(req.Records)
	writeJSON(w, http.StatusOK, models.FingerprintResponse{
		Results: results,
		Total:   len(results),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}
