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

	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

const (
	LocalChatEndpoint = "/v1/chat/completions"

	envelopeSchemaVersion = 1
	maxRequestBytes       = 10 << 20
	maxNormalResponse     = 64 << 20
	maxSSELineTracking    = 1 << 20
)

type sender interface {
	Do(context.Context, string, string, string, []byte) (*http.Response, error)
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
	if len(requestBody) < 2 || requestBody[0] != '{' || requestBody[len(requestBody)-1] != '}' || !json.Valid(requestBody) {
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

	response, err := h.sender.Do(
		r.Context(),
		r.Header.Get("Authorization"),
		r.Header.Get("Accept"),
		r.Header.Get("User-Agent"),
		encodedEnvelope,
	)
	if err != nil {
		h.logger.Printf("confidential Gateway request failed: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway verification or exchange failed", "api_error")
		return
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 ||
		(response.StatusCode >= 300 && response.StatusCode <= 399) ||
		response.StatusCode == http.StatusNoContent || response.StatusCode == http.StatusResetContent {
		h.logger.Printf("confidential Gateway returned body-forbidden HTTP status %d", response.StatusCode)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}

	if isEventStream(response.Header.Get("Content-Type")) {
		h.forwardEventStream(w, response)
		return
	}
	h.forwardNormal(w, response)
}

func (h *Handler) forwardNormal(w http.ResponseWriter, response *http.Response) {
	body, err := jsonutil.ReadAllLimited(response.Body, maxNormalResponse)
	if err != nil {
		h.logger.Printf("read authenticated Gateway response: %v", err)
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) < 2 || body[0] != '{' || body[len(body)-1] != '}' || !json.Valid(body) {
		h.logger.Printf("authenticated Gateway response was not one complete JSON object")
		writeOpenAIError(w, http.StatusBadGateway, "confidential Gateway returned an invalid response", "api_error")
		return
	}
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(response.StatusCode)
	if _, err := w.Write(body); err != nil {
		h.logger.Printf("write local Gateway response: %v", err)
	}
}

func (h *Handler) forwardEventStream(w http.ResponseWriter, response *http.Response) {
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
			tracker.Write(buffer[:count])
			if _, writeErr := w.Write(buffer[:count]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			tracker.Finish()
			if tracker.done {
				return
			}
			h.logger.Printf("authenticated Gateway event stream ended without data: [DONE]")
			panic(http.ErrAbortHandler)
		}
		h.logger.Printf("authenticated Gateway event stream failed: %v", readErr)
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
