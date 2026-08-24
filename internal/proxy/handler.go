// Package proxy implements the localhost OpenAI-compatible HTTP surface.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/catalog"
	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

const (
	LocalChatEndpoint   = "/v1/chat/completions"
	LocalHealthEndpoint = "/healthz"
	LocalModelsEndpoint = catalog.ModelsEndpoint

	LocalVerificationUI       = "/verification"
	LocalVerificationAPI      = "/v1/verification"
	LocalVerificationDocument = "/v1/verification/document"

	envelopeSchemaVersion = 1
	maxRequestBytes       = 10 << 20
	maxNormalResponse     = 64 << 20
	maxSSELineTracking    = 1 << 20

	// catalogTimeout bounds the plain-TLS catalog fetch so a slow Gateway
	// cannot pin a local client's model picker open.
	catalogTimeout = 10 * time.Second
)

// catalogFetcher reads the Gateway's public model catalog. It is a separate
// interface from sender because the catalog is fetched over ordinary TLS with
// no credential, not over the attested EHBP channel.
type catalogFetcher interface {
	Fetch(context.Context) (int, []byte, error)
}

type sender interface {
	// Do returns the response and the identifier of the attested key the
	// request body was encrypted to.
	Do(context.Context, string, string, string, []byte) (*http.Response, string, error)
}

type envelope struct {
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	IssuedAt      string          `json:"issued_at"`
	Request       json.RawMessage `json:"request"`
}

// Handler forwards ordinary local OpenAI requests over an attested EHBP
// channel. It never logs request bodies or Authorization values.
type Handler struct {
	sender sender
	logger *log.Logger
	now    func() time.Time
	newID  func() (string, error)

	ledger        *ledger.Ledger
	gatewayOrigin string
	catalog       catalogFetcher
}

func NewHandler(upstream sender, logger *log.Logger) (*Handler, error) {
	if upstream == nil {
		return nil, errors.New("confidential upstream is required")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	return &Handler{
		sender: upstream,
		logger: logger,
		now:    time.Now,
		newID:  randomUUID,
	}, nil
}

// WithVerification serves the local verification surface from record and
// stores per request metadata in it. Request and response bodies are never
// stored. gatewayOrigin is shown in the UI so an operator can see which
// Gateway the evidence belongs to.
func (h *Handler) WithVerification(record *ledger.Ledger, gatewayOrigin string) *Handler {
	h.ledger = record
	h.gatewayOrigin = gatewayOrigin
	return h
}

// WithModelCatalog serves GET /v1/models by passing the Gateway's public
// model catalog through unchanged. Without it that path 404s, and the proxy
// exposes nothing but the confidential inference endpoint.
func (h *Handler) WithModelCatalog(source catalogFetcher) *Handler {
	h.catalog = source
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == LocalHealthEndpoint {
		h.serveHealth(w, r)
		return
	}
	switch r.URL.Path {
	case LocalVerificationUI:
		h.serveVerificationUI(w, r)
		return
	case LocalVerificationAPI:
		h.serveVerificationAPI(w, r)
		return
	case LocalVerificationDocument:
		h.serveVerificationDocument(w, r)
		return
	case LocalModelsEndpoint:
		h.serveModels(w, r)
		return
	}
	if r.URL.Path != LocalChatEndpoint {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method must be POST", "invalid_request_error")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeOpenAIError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json", "invalid_request_error")
		return
	}

	requestBody, err := jsonutil.ReadAllLimited(r.Body, maxRequestBytes)
	if err != nil {
		writeOpenAIError(w, http.StatusRequestEntityTooLarge, "request body exceeds the 10 MiB limit", "invalid_request_error")
		return
	}
	requestBody = bytes.TrimSpace(requestBody)
	if !jsonutil.IsJSONObject(requestBody) {
		writeOpenAIError(w, http.StatusBadRequest, "request body must be one JSON object", "invalid_request_error")
		return
	}

	requestID, err := h.newID()
	if err != nil {
		h.logger.Printf("generate confidential request ID: %v", err)
		writeOpenAIError(w, http.StatusInternalServerError, "local proxy failed to prepare request", "api_error")
		return
	}
	encodedEnvelope, err := json.Marshal(envelope{
		SchemaVersion: envelopeSchemaVersion,
		RequestID:     requestID,
		IssuedAt:      h.now().UTC().Format(time.RFC3339Nano),
		Request:       append(json.RawMessage(nil), requestBody...),
	})
	if err != nil {
		h.logger.Printf("encode confidential request envelope: %v", err)
		writeOpenAIError(w, http.StatusInternalServerError, "local proxy failed to prepare request", "api_error")
		return
	}

	started := h.now()
	record := ledger.Request{
		ID:           requestID,
		StartedAt:    started.UTC(),
		Outcome:      ledger.OutcomeFailed,
		RequestBytes: len(requestBody),
	}
	defer func() {
		record.DurationMS = h.now().Sub(started).Milliseconds()
		h.ledger.RecordRequest(record)
	}()

	response, attestationID, err := h.sender.Do(
		r.Context(),
		r.Header.Get("Authorization"),
		r.Header.Get("Accept"),
		r.Header.Get("User-Agent"),
		encodedEnvelope,
	)
	record.AttestationID = attestationID
	if err != nil {
		record.Failure = "Gateway attestation or encrypted exchange failed"
		h.logger.Printf("confidential Gateway request failed: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway verification or exchange failed", "api_error")
		return
	}
	defer response.Body.Close()
	record.StatusCode = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode > 599 ||
		(response.StatusCode >= 300 && response.StatusCode <= 399) ||
		response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusResetContent {
		record.Failure = "Gateway returned a status that forbids a body"
		h.logger.Printf("confidential Gateway returned body-forbidden HTTP status %d", response.StatusCode)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}

	if isEventStream(response.Header.Get("Content-Type")) {
		record.Streaming = true
		h.forwardEventStream(r.Context(), w, response, &record)
		return
	}
	h.forwardNormal(w, response, &record)
}

func (h *Handler) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method must be GET", "invalid_request_error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "{\"status\":\"ok\"}\n")
}

// serveModels passes the Gateway's public model catalog through so the local
// proxy is a drop-in OpenAI base URL. The catalog carries no prompt or
// completion content, so this request is not encrypted, not attested and not
// recorded in the verification ledger — recording it there would inflate the
// count of bodies that actually crossed the confidential channel.
func (h *Handler) serveModels(w http.ResponseWriter, r *http.Request) {
	if h.catalog == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeOpenAIError(w, http.StatusMethodNotAllowed, "method must be GET", "invalid_request_error")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogTimeout)
	defer cancel()
	status, body, err := h.catalog.Fetch(ctx)
	if err != nil {
		h.logger.Printf("fetch Gateway model catalog: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "could not read the model catalog from the Gateway", "api_error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		h.logger.Printf("write local model catalog response: %v", err)
	}
}

func (h *Handler) forwardNormal(w http.ResponseWriter, response *http.Response, record *ledger.Request) {
	body, err := jsonutil.ReadAllLimited(response.Body, maxNormalResponse)
	if err != nil {
		record.Failure = "authenticated response could not be read"
		h.logger.Printf("read authenticated Gateway response: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}
	body = bytes.TrimSpace(body)
	if !jsonutil.IsJSONObject(body) {
		record.Failure = "authenticated response was not one complete JSON object"
		h.logger.Printf("authenticated Gateway response was not one complete JSON object")
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}
	record.Outcome = ledger.OutcomeEncrypted
	record.ResponseBytes = int64(len(body))
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	if _, err := w.Write(body); err != nil {
		h.logger.Printf("write local Gateway response: %v", err)
	}
}

func (h *Handler) forwardEventStream(ctx context.Context, w http.ResponseWriter, response *http.Response, record *ledger.Request) {
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(response.Body)
	tracker := newSSEDoneTracker()
	buffer := make([]byte, 32<<10)
	for {
		count, readErr := reader.Read(buffer)
		if count > 0 {
			record.ResponseBytes += int64(count)
			tracker.Write(buffer[:count])
			if _, writeErr := w.Write(buffer[:count]); writeErr != nil {
				record.Failure = "local client disconnected mid-stream"
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr == nil {
			continue
		}

		// The upstream stream is over, cleanly or not. Decide on the
		// terminator, not on how the read ended: "data: [DONE]" IS the end of
		// an SSE response, so once it has been delivered and flushed there is
		// nothing further to authenticate and the exchange succeeded.
		//
		// This matters because a well-behaved OpenAI client closes the
		// response body the moment it reads [DONE]. That cancels the request
		// context, which tears down the upstream request, and the frame guard
		// reports the half-read length prefix as "truncated EHBP response
		// frame prefix" — a non-EOF error arriving after a complete, fully
		// authenticated response. Treating that as a failure aborted a
		// connection the client had already finished with and recorded every
		// such request as failed in the verification ledger.
		//
		// A stream cut BEFORE the terminator still fails closed below, so the
		// integrity property is unchanged: bytes released to the local client
		// were always authenticated, and a response that never completed is
		// never reported as if it had.
		tracker.Finish()
		if tracker.done {
			record.Outcome = ledger.OutcomeEncrypted
			return
		}

		switch {
		case errors.Is(readErr, io.EOF):
			record.Failure = "authenticated event stream ended without a terminating [DONE]"
			h.logger.Printf("authenticated Gateway event stream ended without data: [DONE]")
		case ctx.Err() != nil:
			// The local client went away before the response completed. That
			// is not the Gateway failing, and saying so would send an operator
			// looking in the wrong place.
			record.Failure = "local client disconnected mid-stream"
		default:
			record.Failure = "authenticated event stream failed mid-response"
			h.logger.Printf("authenticated Gateway event stream failed: %v", readErr)
		}
		panic(http.ErrAbortHandler)
	}
}

func isEventStream(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "text/event-stream")
}

func copyResponseHeaders(destination, source http.Header) {
	connectionHeaders := make(map[string]struct{})
	for _, value := range source.Values("Connection") {
		for item := range strings.SplitSeq(value, ",") {
			connectionHeaders[http.CanonicalHeaderKey(strings.TrimSpace(item))] = struct{}{}
		}
	}
	for key, values := range source {
		canonical := http.CanonicalHeaderKey(key)
		if isHopByHopHeader(canonical) || canonical == "Content-Length" ||
			canonical == "Ehbp-Response-Nonce" || canonical == "Ehbp-Encapsulated-Key" {
			continue
		}
		if _, blocked := connectionHeaders[canonical]; blocked {
			continue
		}
		if !allowedResponseHeader(canonical) {
			continue
		}
		for _, value := range values {
			destination.Add(canonical, value)
		}
	}
}

func allowedResponseHeader(header string) bool {
	lower := strings.ToLower(header)
	return lower == "retry-after" || lower == "request-id" ||
		lower == "x-request-id" || lower == "openai-request-id" || strings.HasPrefix(lower, "x-ratelimit-")
}

func isHopByHopHeader(header string) bool {
	switch header {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	default:
		return false
	}
}

func writeOpenAIError(w http.ResponseWriter, status int, message, errorType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}{Error: struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}{Message: message, Type: errorType}})
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	raw := hex.EncodeToString(value[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", raw[0:8], raw[8:12], raw[12:16], raw[16:20], raw[20:32]), nil
}

type sseDoneTracker struct {
	line    []byte
	tooLong bool
	done    bool
}

func newSSEDoneTracker() *sseDoneTracker {
	return &sseDoneTracker{line: make([]byte, 0, 128)}
}

func (t *sseDoneTracker) Write(data []byte) {
	for _, current := range data {
		if current == '\n' {
			t.finishLine()
			continue
		}
		if t.tooLong {
			continue
		}
		if len(t.line) == maxSSELineTracking {
			t.line = t.line[:0]
			t.tooLong = true
			continue
		}
		t.line = append(t.line, current)
	}
}

func (t *sseDoneTracker) Finish() {
	if len(t.line) > 0 || t.tooLong {
		t.finishLine()
	}
}

func (t *sseDoneTracker) finishLine() {
	if !t.tooLong && bytes.Equal(bytes.TrimSpace(t.line), []byte("data: [DONE]")) {
		t.done = true
	}
	t.line = t.line[:0]
	t.tooLong = false
}
