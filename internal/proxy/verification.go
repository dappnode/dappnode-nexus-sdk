package proxy

import (
	_ "embed"
	"encoding/json"
	"net/http"

	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

//go:embed verification.html
var verificationPage []byte

type verificationView struct {
	Gateway string `json:"gateway"`
	ledger.Snapshot
}

func (h *Handler) serveVerificationUI(w http.ResponseWriter, r *http.Request) {
	if !h.allowVerification(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(verificationPage)
}

func (h *Handler) serveVerificationAPI(w http.ResponseWriter, r *http.Request) {
	if !h.allowVerification(w, r) {
		return
	}
	view := verificationView{Gateway: h.gatewayOrigin, Snapshot: h.ledger.Snapshot()}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(view); err != nil {
		h.logger.Printf("write verification snapshot: %v", err)
	}
}

// serveVerificationDocument returns signed evidence verbatim so it can be
// re-checked with an independent AWS Nitro verifier.
func (h *Handler) serveVerificationDocument(w http.ResponseWriter, r *http.Request) {
	if !h.allowVerification(w, r) {
		return
	}
	id := r.URL.Query().Get("id")
	document, manifest, found := h.ledger.Document(id)
	if !found {
		writeOpenAIError(w, http.StatusNotFound, "no retained evidence for that attestation", "invalid_request_error")
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("part") == "manifest" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"nexus-manifest-"+id+".json\"")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(manifest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\"nexus-attestation-"+id+".cose\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(document)
}

func (h *Handler) allowVerification(w http.ResponseWriter, r *http.Request) bool {
	if !h.verificationUI || h.ledger == nil {
		http.NotFound(w, r)
		return false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method must be GET", "invalid_request_error")
		return false
	}
	return true
}
