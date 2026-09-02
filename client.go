package nexus

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/catalog"
	"github.com/dappnode/dappnode-nexus-sdk/internal/confidential"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
	"github.com/dappnode/dappnode-nexus-sdk/internal/proxy"
)

const (
	// InProcessBaseURL is the OpenAI-compatible base URL to use with an HTTP
	// client returned by Client.HTTPClient. Requests never leave the process at
	// this URL; the custom transport sends them directly to Client.Handler.
	InProcessBaseURL = "http://nexus.local/v1"

	ChatCompletionsPath = "/v1/chat/completions"
	ModelsPath          = "/v1/models"
	HealthPath          = "/healthz"
	VerificationPath    = "/verification"

	StatusStarting   = "starting"
	OutcomeVerified  = "verified"
	OutcomeRejected  = "rejected"
	OutcomeEncrypted = "encrypted"
	OutcomeFailed    = "failed"

	defaultAttestationTimeout = 15 * time.Second
)

// ErrEvidenceNotFound is returned when verification evidence is no longer in
// the bounded local history or the supplied identifier is unknown.
var ErrEvidenceNotFound = errors.New("verification evidence not found")

// Config describes a Nexus SDK client. GatewayURL and exactly one of
// TrustPolicyFile or TrustPolicyJSON are required. The SDK constructs its own
// hardened network transports so callers cannot accidentally weaken redirect
// or encrypted-frame checks.
type Config struct {
	GatewayURL         string
	TrustPolicyFile    string
	TrustPolicyJSON    []byte
	AttestationTimeout time.Duration

	// StateFile enables persistence of verification evidence and request
	// metadata. Prompt and response content is never stored. Empty keeps history
	// in memory only. Call Close or Flush to write pending changes.
	StateFile string

	// These switches affect routes exposed by Handler and HTTPClient. Direct
	// verification remains available through Verify and Verification.
	DisableVerificationUI bool
	DisableModelCatalog   bool

	// Logger receives operational errors and never receives API keys, prompts,
	// or responses. Nil discards library logs.
	Logger *log.Logger
}

// Client is an attestation-verified Nexus client. It is safe for concurrent
// use. New returns only after the Gateway has passed initial verification.
type Client struct {
	gatewayURL   string
	timeout      time.Duration
	confidential *confidential.Client
	handler      http.Handler
	ledger       *ledger.Ledger
}

// New constructs a Nexus client and verifies the Gateway before returning.
// No prompt can be sent through the returned client before this succeeds.
func New(ctx context.Context, config Config) (*Client, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	gatewayURL, timeout, err := validateConfig(config)
	if err != nil {
		return nil, err
	}

	var policy *attestation.Policy
	if len(config.TrustPolicyJSON) > 0 {
		policy, err = attestation.ParsePolicy(config.TrustPolicyJSON)
	} else {
		policy, err = attestation.LoadPolicy(config.TrustPolicyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("load trust policy: %w", err)
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not configurable")
	}
	transport := defaultTransport.Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	wireClient := &http.Client{
		Transport:     confidential.GuardEHBPResponses(transport),
		CheckRedirect: rejectRedirects,
	}
	plainClient := &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: rejectRedirects,
	}

	verifier, err := attestation.NewVerifier(
		gatewayURL+"/v1/attestation",
		policy,
		plainClient,
	)
	if err != nil {
		return nil, fmt.Errorf("configure attestation verifier: %w", err)
	}
	confidentialClient, err := confidential.NewClient(
		gatewayURL+attestation.ConfidentialEndpoint,
		verifier,
		wireClient,
	)
	if err != nil {
		return nil, fmt.Errorf("configure confidential Gateway client: %w", err)
	}

	verificationLedger := ledger.New()
	if config.StateFile != "" {
		verificationLedger, err = ledger.Open(config.StateFile)
		if err != nil {
			return nil, fmt.Errorf("open verification state file: %w", err)
		}
	}
	confidentialClient = confidentialClient.WithLedger(verificationLedger)

	verifyContext, cancelVerify := context.WithTimeout(ctx, timeout)
	err = confidentialClient.WarmUp(verifyContext)
	cancelVerify()
	if err != nil {
		return nil, fmt.Errorf("initial Gateway attestation failed: %w", err)
	}

	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	handler, err := proxy.NewHandler(confidentialClient, logger)
	if err != nil {
		return nil, fmt.Errorf("configure OpenAI-compatible handler: %w", err)
	}
	handler = handler.WithLedger(verificationLedger)
	if !config.DisableVerificationUI {
		handler = handler.WithVerification(verificationLedger, gatewayURL)
	}
	if !config.DisableModelCatalog {
		catalogClient, err := catalog.NewClient(gatewayURL+catalog.ModelsEndpoint, plainClient)
		if err != nil {
			return nil, fmt.Errorf("configure model catalog client: %w", err)
		}
		handler = handler.WithModelCatalog(catalogClient)
	}

	return &Client{
		gatewayURL:   gatewayURL,
		timeout:      timeout,
		confidential: confidentialClient,
		handler:      handler,
		ledger:       verificationLedger,
	}, nil
}

// GatewayURL returns the normalized HTTPS origin this client verifies.
func (c *Client) GatewayURL() string {
	if c == nil {
		return ""
	}
	return c.gatewayURL
}

// Handler returns the OpenAI-compatible HTTP handler. It includes chat
// completions, health, model catalog, and verification routes according to the
// Config used by New. The application controls where and whether it listens.
func (c *Client) Handler() http.Handler {
	if c == nil {
		return nil
	}
	return c.handler
}

// HTTPClient returns an in-process HTTP client backed by Handler. Use
// InProcessBaseURL as the base URL when passing this client to another Go SDK.
// No local TCP listener is created.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport:     handlerTransport{handler: c.Handler()},
		CheckRedirect: rejectRedirects,
	}
}

// ChatCompletions sends one OpenAI-compatible chat completion through the
// verified encrypted channel. The response body may be a normal JSON response
// or an event stream and must be closed by the caller.
func (c *Client) ChatCompletions(ctx context.Context, apiKey string, body []byte) (*http.Response, error) {
	if c == nil || c.handler == nil {
		return nil, errors.New("Nexus client is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("Nexus API key is required")
	}
	if len(bytes.TrimSpace(body)) == 0 || !json.Valid(body) {
		return nil, errors.New("chat completion body must be valid JSON")
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		InProcessBaseURL+"/chat/completions",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create chat completion request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	return c.HTTPClient().Do(request)
}

// Models retrieves the Gateway's public OpenAI-compatible model catalog. The
// response body must be closed by the caller.
func (c *Client) Models(ctx context.Context) (*http.Response, error) {
	if c == nil || c.handler == nil {
		return nil, errors.New("Nexus client is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, InProcessBaseURL+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("create model catalog request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	return c.HTTPClient().Do(request)
}

// Verify discards the cached verified session, obtains fresh attestation
// evidence, and returns the successful verification record. Concurrent
// requests remain safe and will use a verified session.
func (c *Client) Verify(ctx context.Context) (*Attestation, error) {
	if c == nil || c.confidential == nil {
		return nil, errors.New("Nexus client is nil")
	}
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	verifyContext, cancelVerify := context.WithTimeout(ctx, c.timeout)
	err := c.confidential.Reverify(verifyContext)
	cancelVerify()
	if err != nil {
		return nil, fmt.Errorf("verify Gateway: %w", err)
	}
	snapshot := c.Verification()
	if snapshot.Current == nil {
		return nil, errors.New("verification succeeded without a current record")
	}
	return snapshot.Current, nil
}

// Verification returns a copy of the current verification and request
// history. It never contains prompts, responses, or API keys.
func (c *Client) Verification() Snapshot {
	if c == nil || c.ledger == nil {
		return Snapshot{Status: StatusStarting, GeneratedAt: time.Now().UTC()}
	}
	return snapshotFromLedger(c.ledger.Snapshot())
}

// Evidence returns the signed attestation document and manifest for a
// verification record. The returned byte slices are independent copies.
func (c *Client) Evidence(id string) (*Evidence, error) {
	if c == nil || c.ledger == nil {
		return nil, errors.New("Nexus client is nil")
	}
	document, manifest, ok := c.ledger.Document(id)
	if !ok {
		return nil, ErrEvidenceNotFound
	}
	return &Evidence{
		AttestationID: id,
		Document:      append([]byte(nil), document...),
		Manifest:      append(json.RawMessage(nil), manifest...),
	}, nil
}

// Flush persists verification history when Config.StateFile is set. It is a
// no-op for an in-memory client.
func (c *Client) Flush() error {
	if c == nil || c.ledger == nil {
		return nil
	}
	return c.ledger.Flush()
}

// Close flushes persistent verification history. The Client owns no listener;
// an application embedding Handler remains responsible for its HTTP server.
func (c *Client) Close() error {
	return c.Flush()
}

func validateConfig(config Config) (string, time.Duration, error) {
	gatewayURL, err := normalizeGatewayURL(config.GatewayURL)
	if err != nil {
		return "", 0, err
	}
	hasPolicyFile := strings.TrimSpace(config.TrustPolicyFile) != ""
	hasPolicyJSON := len(config.TrustPolicyJSON) > 0
	if hasPolicyFile == hasPolicyJSON {
		return "", 0, errors.New("exactly one of trust policy file or JSON is required")
	}
	timeout := config.AttestationTimeout
	if timeout == 0 {
		timeout = defaultAttestationTimeout
	}
	if timeout < 0 {
		return "", 0, errors.New("attestation timeout must be positive")
	}
	return gatewayURL, timeout, nil
}

func normalizeGatewayURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("Gateway URL is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("invalid Gateway URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "", errors.New("Gateway URL must be an absolute HTTPS origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", errors.New("Gateway URL must not contain credentials, a query, or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("Gateway URL must be an origin without a path")
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(), nil
}

func rejectRedirects(_ *http.Request, _ []*http.Request) error {
	return errors.New("redirects are not allowed")
}

type handlerTransport struct {
	handler http.Handler
}

func (transport handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.handler == nil {
		return nil, errors.New("Nexus handler is nil")
	}
	if request == nil || request.URL == nil {
		return nil, errors.New("HTTP request and URL are required")
	}
	if request.URL.Scheme != "http" || request.URL.Host != "nexus.local" {
		return nil, fmt.Errorf("in-process Nexus requests must use %s", InProcessBaseURL)
	}

	reader, writer := io.Pipe()
	responseWriter := newInProcessResponseWriter(writer)
	go func() {
		if request.Body != nil {
			defer request.Body.Close()
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					responseWriter.finish(io.ErrUnexpectedEOF)
					return
				}
				responseWriter.finish(fmt.Errorf("embedded Nexus handler panic: %v", recovered))
				return
			}
			responseWriter.finish(nil)
		}()
		transport.handler.ServeHTTP(responseWriter, request)
	}()

	select {
	case <-responseWriter.ready:
		if err := request.Context().Err(); err != nil {
			reader.Close()
			return nil, err
		}
		if responseWriter.terminalErr != nil {
			reader.Close()
			return nil, responseWriter.terminalErr
		}
		if responseWriter.status == 0 {
			reader.Close()
			return nil, errors.New("embedded Nexus handler returned no status")
		}
		return &http.Response{
			Status:        fmt.Sprintf("%d %s", responseWriter.status, http.StatusText(responseWriter.status)),
			StatusCode:    responseWriter.status,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        responseWriter.responseHeader.Clone(),
			Body:          reader,
			ContentLength: -1,
			Request:       request,
		}, nil
	case <-request.Context().Done():
		responseWriter.finish(request.Context().Err())
		reader.Close()
		return nil, request.Context().Err()
	}
}

type inProcessResponseWriter struct {
	header         http.Header
	responseHeader http.Header
	status         int
	terminalErr    error
	pipe           *io.PipeWriter
	ready          chan struct{}
	readyOnce      sync.Once
	finishOnce     sync.Once
}

func newInProcessResponseWriter(pipe *io.PipeWriter) *inProcessResponseWriter {
	return &inProcessResponseWriter{
		header: make(http.Header),
		pipe:   pipe,
		ready:  make(chan struct{}),
	}
}

func (writer *inProcessResponseWriter) Header() http.Header {
	return writer.header
}

func (writer *inProcessResponseWriter) WriteHeader(status int) {
	writer.readyOnce.Do(func() {
		writer.status = status
		writer.responseHeader = writer.header.Clone()
		close(writer.ready)
	})
}

func (writer *inProcessResponseWriter) Write(data []byte) (int, error) {
	writer.WriteHeader(http.StatusOK)
	return writer.pipe.Write(data)
}

func (writer *inProcessResponseWriter) Flush() {
	writer.WriteHeader(http.StatusOK)
}

func (writer *inProcessResponseWriter) finish(err error) {
	writer.finishOnce.Do(func() {
		if err != nil {
			writer.readyOnce.Do(func() {
				writer.terminalErr = err
				close(writer.ready)
			})
			_ = writer.pipe.CloseWithError(err)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_ = writer.pipe.Close()
	})
}
