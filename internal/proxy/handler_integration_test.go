package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/confidential"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

const (
	promptCanary     = "PROMPT-CANARY-37ac8a"
	completionCanary = "COMPLETION-CANARY-91dd72"
)

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type fakeEvidenceVerifier struct {
	mu    sync.Mutex
	key   []byte
	calls int
}

func (v *fakeEvidenceVerifier) Verify(context.Context) (*attestation.Evidence, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	return &attestation.Evidence{
		PublicKey:  append([]byte(nil), v.key...),
		AttestedAt: time.Now().Add(-time.Second),
		ExpiresAt:  time.Now().Add(time.Minute),
	}, nil
}

func (v *fakeEvidenceVerifier) setKey(key []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.key = append([]byte(nil), key...)
}

func (v *fakeEvidenceVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

type gatewayCapture struct {
	mu sync.Mutex

	requestHeaders http.Header
	requestBody    []byte
	responseBody   []byte
	requestCount   int
}

func (c *gatewayCapture) recordRequest(header http.Header, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestHeaders = header.Clone()
	c.requestBody = append([]byte(nil), body...)
	c.requestCount++
}

func (c *gatewayCapture) recordResponse(body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responseBody = append([]byte(nil), body...)
}

func (c *gatewayCapture) snapshot() (http.Header, []byte, []byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requestHeaders.Clone(), append([]byte(nil), c.requestBody...), append([]byte(nil), c.responseBody...), c.requestCount
}

type capturingResponseWriter struct {
	http.ResponseWriter
	body bytes.Buffer
}

func (w *capturingResponseWriter) Write(data []byte) (int, error) {
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *capturingResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func newCapturedEHBPServer(t *testing.T, serverIdentity *identity.Identity, application http.Handler) (*httptest.Server, *gatewayCapture) {
	t.Helper()
	capture := &gatewayCapture{}
	encrypted := serverIdentity.Middleware()(application)
	strict := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(protocol.EncapsulatedKeyHeader)
		if len(values) != 1 || len(values[0]) != 64 || strings.ToLower(values[0]) != values[0] {
			http.Error(w, "encrypted request required", http.StatusBadRequest)
			return
		}
		if decoded, err := hex.DecodeString(values[0]); err != nil || len(decoded) != 32 {
			http.Error(w, "encrypted request required", http.StatusBadRequest)
			return
		}
		encrypted.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wireBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read wire request", http.StatusBadRequest)
			return
		}
		capture.recordRequest(r.Header, wireBody)
		r.Body = io.NopCloser(bytes.NewReader(wireBody))
		r.ContentLength = -1
		writer := &capturingResponseWriter{ResponseWriter: w}
		strict.ServeHTTP(writer, r)
		capture.recordResponse(writer.body.Bytes())
	}))
	t.Cleanup(server.Close)
	return server, capture
}

func newLocalProxy(t *testing.T, gatewayURL string, verifier *fakeEvidenceVerifier, wireTransport http.RoundTripper) *httptest.Server {
	t.Helper()
	if wireTransport == nil {
		t.Fatal("test wire transport is required")
	}
	wireClient := &http.Client{
		Transport: confidential.GuardEHBPResponses(wireTransport),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
	client, err := confidential.NewClient(gatewayURL+attestation.ConfidentialEndpoint, verifier, wireClient)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func TestEndToEndNormalBodyPrivacyAndCompatibility(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var observed envelope
	var applicationError atomic.Value
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&observed); err != nil {
			applicationError.Store(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "gateway-request-123")
		w.Header().Set("Set-Cookie", "must-not-cross=true")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-test","choices":[{"message":{"content":"`+completionCanary+`"}}]}`)
	})
	gateway, capture := newCapturedEHBPServer(t, serverIdentity, application)
	verifier := &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}
	local := newLocalProxy(t, gateway.URL, verifier, gateway.Client().Transport)

	requestBody := `{"model":"test","messages":[{"role":"user","content":"` + promptCanary + `"}]}`
	request, err := http.NewRequest(http.MethodPost, local.URL+LocalChatEndpoint, strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer nexus-secret-key")
	request.Header.Set("Accept", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(completionCanary)) {
		t.Fatalf("local response = HTTP %d %s", response.StatusCode, body)
	}
	if response.Header.Get("X-Request-Id") != "gateway-request-123" {
		t.Fatalf("X-Request-Id = %q", response.Header.Get("X-Request-Id"))
	}
	if response.Header.Get("Set-Cookie") != "" || response.Header.Get(protocol.ResponseNonceHeader) != "" {
		t.Fatalf("unsafe outer response headers crossed proxy: %v", response.Header)
	}
	if value := applicationError.Load(); value != nil {
		t.Fatalf("Gateway application error = %v", value)
	}
	if observed.SchemaVersion != envelopeSchemaVersion || !canonicalUUID.MatchString(observed.RequestID) {
		t.Fatalf("invalid envelope metadata: %+v", observed)
	}
	if _, err := time.Parse(time.RFC3339Nano, observed.IssuedAt); err != nil {
		t.Fatalf("issued_at = %q: %v", observed.IssuedAt, err)
	}
	if string(observed.Request) != requestBody {
		t.Fatalf("decrypted request = %s, want %s", observed.Request, requestBody)
	}

	headers, encryptedRequest, encryptedResponse, requestCount := capture.snapshot()
	if requestCount != 1 || verifier.callCount() != 1 {
		t.Fatalf("wire requests = %d, attestations = %d; want 1 and 1", requestCount, verifier.callCount())
	}
	if headers.Get("Authorization") != "Bearer nexus-secret-key" {
		t.Fatalf("visible Authorization = %q", headers.Get("Authorization"))
	}
	if headers.Get(protocol.EncapsulatedKeyHeader) == "" {
		t.Fatal("wire request is missing EHBP encapsulated key")
	}
	if bytes.Contains(encryptedRequest, []byte(promptCanary)) || bytes.Contains(encryptedRequest, []byte("messages")) {
		t.Fatalf("wire request leaked plaintext: %q", encryptedRequest)
	}
	if bytes.Contains(encryptedResponse, []byte(completionCanary)) || bytes.Contains(encryptedResponse, []byte("choices")) {
		t.Fatalf("wire response leaked plaintext: %q", encryptedResponse)
	}
}

func TestEndToEndStreamingFlushesAuthenticatedEvents(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, `data: {"choices":[{"delta":{"content":"`+completionCanary+`"}}]}`+"\n\n")
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
		w.(http.Flusher).Flush()
	})
	gateway, capture := newCapturedEHBPServer(t, serverIdentity, application)
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, gateway.Client().Transport)

	request, err := http.NewRequest(http.MethodPost, local.URL+LocalChatEndpoint, strings.NewReader(`{"model":"test","stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer visible-key")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first streamed event: %v", err)
	}
	if !strings.Contains(firstLine, completionCanary) {
		t.Fatalf("first streamed line = %q", firstLine)
	}
	close(release)
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rest, []byte("data: [DONE]")) {
		t.Fatalf("stream tail = %q", rest)
	}
	_, _, encryptedResponse, _ := capture.snapshot()
	if bytes.Contains(encryptedResponse, []byte(completionCanary)) {
		t.Fatalf("wire stream leaked completion: %q", encryptedResponse)
	}
}

func TestStreamingWithoutDoneAbortsLocalConnection(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"partial\":true}\n\n")
		w.(http.Flusher).Flush()
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, gateway.Client().Transport)

	request, err := http.NewRequest(http.MethodPost, local.URL+LocalChatEndpoint, strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, readErr := io.ReadAll(response.Body)
	if readErr == nil {
		t.Fatal("truncated SSE stream ended as a successful HTTP response")
	}
}

type tamperingTransport struct {
	next http.RoundTripper
}

func (t *tamperingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Header.Get(protocol.ResponseNonceHeader) == "" {
		return response, nil
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		body[len(body)-1] ^= 0xff
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

type plaintextSubstitutionTransport struct{}

func (*plaintextSubstitutionTransport) RoundTrip(*http.Request) (*http.Response, error) {
	body := `{"completion":"attacker-substitution"}`
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}, nil
}

type boundaryTruncatingTransport struct {
	next http.RoundTripper
}

func (t *boundaryTruncatingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.Header.Get(protocol.ResponseNonceHeader) == "" {
		return response, nil
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) < 4 {
		return nil, errors.New("test response did not contain an EHBP frame")
	}
	firstFrameEnd := 4 + int(uint32(body[0])<<24|uint32(body[1])<<16|uint32(body[2])<<8|uint32(body[3]))
	if firstFrameEnd >= len(body) {
		return nil, errors.New("test response did not contain multiple EHBP frames")
	}
	body = body[:firstFrameEnd]
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

type statusTamperingTransport struct {
	next     http.RoundTripper
	status   int
	location string
}

func (t *statusTamperingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.next.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.StatusCode = t.status
	response.Status = http.StatusText(t.status)
	if t.location != "" {
		response.Header.Set("Location", t.location)
	}
	return response, nil
}

func TestTamperedCompletionFailsBeforeNormalResponseIsForwarded(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"completion":"`+completionCanary+`"}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	tamper := &tamperingTransport{next: gateway.Client().Transport}
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, tamper)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"`+promptCanary+`"}`, "Bearer key")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte(completionCanary)) {
		t.Fatalf("tampered response = HTTP %d %s", response.StatusCode, body)
	}
}

func TestPlaintextResponseSubstitutionFailsClosed(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	local := newLocalProxy(
		t,
		"https://gateway.example",
		&fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()},
		&plaintextSubstitutionTransport{},
	)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"test"}`, "Bearer key")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte("attacker-substitution")) {
		t.Fatalf("substituted response = HTTP %d %s", response.StatusCode, body)
	}
}

func TestNormalResponseTruncatedAtAuthenticatedFrameBoundaryFailsClosed(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"completion":"`)
		_, _ = io.WriteString(w, completionCanary+`"}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	truncate := &boundaryTruncatingTransport{next: gateway.Client().Transport}
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, truncate)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"test"}`, "Bearer key")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte(completionCanary)) {
		t.Fatalf("frame-truncated response = HTTP %d %s", response.StatusCode, body)
	}
}

func TestBodyForbiddenOuterStatusFailsClosed(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"completion":"`+completionCanary+`"}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	statusTamper := &statusTamperingTransport{next: gateway.Client().Transport, status: http.StatusNoContent}
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, statusTamper)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"test"}`, "Bearer key")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte(completionCanary)) {
		t.Fatalf("status-tampered response = HTTP %d %s", response.StatusCode, body)
	}
}

func TestForgedGatewayRedirectNeverReachesLocalClientTarget(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"completion":"authenticated"}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	var targetCalls atomic.Int64
	var targetBody atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		targetBody.Store(string(body))
	}))
	defer target.Close()
	statusTamper := &statusTamperingTransport{
		next:     gateway.Client().Transport,
		status:   http.StatusTemporaryRedirect,
		location: target.URL,
	}
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, statusTamper)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"`+promptCanary+`"}`, "Bearer key")
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("local response status = %d, want 502", response.StatusCode)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target calls = %d, body = %v", targetCalls.Load(), targetBody.Load())
	}
}

func TestOutboundGatewayRedirectIsNeverFollowed(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var targetCalls atomic.Int64
	var targetBody atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		body, _ := io.ReadAll(r.Body)
		targetBody.Store(string(body))
	}))
	defer target.Close()
	var gatewayCalls atomic.Int64
	gateway := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayCalls.Add(1)
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer gateway.Close()
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, gateway.Client().Transport)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"`+promptCanary+`"}`, "Bearer key")
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("local response status = %d, want 502", response.StatusCode)
	}
	if gatewayCalls.Load() != 1 || targetCalls.Load() != 0 {
		t.Fatalf("gateway calls = %d, redirect target calls = %d, target body = %v", gatewayCalls.Load(), targetCalls.Load(), targetBody.Load())
	}
}

func TestKeyRotationFailsWithoutReplayAndReattestsNextCallerRequest(t *testing.T) {
	activeIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	staleIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var applicationCalls atomic.Int64
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applicationCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	gateway, capture := newCapturedEHBPServer(t, activeIdentity, application)
	verifier := &fakeEvidenceVerifier{key: staleIdentity.MarshalPublicKey()}
	local := newLocalProxy(t, gateway.URL, verifier, gateway.Client().Transport)

	first := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"first"}`, "Bearer key")
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusBadGateway {
		t.Fatalf("first response = HTTP %d %s", first.StatusCode, firstBody)
	}
	_, _, _, wireRequests := capture.snapshot()
	if wireRequests != 1 || applicationCalls.Load() != 0 || verifier.callCount() != 1 {
		t.Fatalf("after stale key: wire=%d app=%d attest=%d; request must not retry", wireRequests, applicationCalls.Load(), verifier.callCount())
	}

	verifier.setKey(activeIdentity.MarshalPublicKey())
	second := postJSON(t, local.URL+LocalChatEndpoint, `{"prompt":"second"}`, "Bearer key")
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusOK || !bytes.Contains(secondBody, []byte(`"ok":true`)) {
		t.Fatalf("second response = HTTP %d %s", second.StatusCode, secondBody)
	}
	if applicationCalls.Load() != 1 || verifier.callCount() != 2 {
		t.Fatalf("after caller retry: app=%d attest=%d, want 1 and 2", applicationCalls.Load(), verifier.callCount())
	}
}

func TestEncryptedAuthenticationErrorIsForwarded(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid API key","type":"authentication_error"}}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	local := newLocalProxy(t, gateway.URL, &fakeEvidenceVerifier{key: serverIdentity.MarshalPublicKey()}, gateway.Client().Transport)

	response := postJSON(t, local.URL+LocalChatEndpoint, `{"model":"test"}`, "Bearer invalid")
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized || !bytes.Contains(body, []byte("invalid API key")) {
		t.Fatalf("authentication response = HTTP %d %s", response.StatusCode, body)
	}
}

func postJSON(t *testing.T, endpoint, body, authorization string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
