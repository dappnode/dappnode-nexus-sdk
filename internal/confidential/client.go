// Package confidential creates EHBP clients exclusively from fresh,
// attestation-verified Nexus Gateway keys.
package confidential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

type evidenceVerifier interface {
	Verify(context.Context) (*attestation.Evidence, error)
}

type verifiedSession struct {
	client        *http.Client
	expiresAt     time.Time
	attestationID string
}

// Client maintains a short-lived EHBP session derived from fresh Nitro
// evidence. It never uses EHBP key discovery.
type Client struct {
	endpoint string
	verifier evidenceVerifier
	wire     *http.Client
	now      func() time.Time
	ledger   *ledger.Ledger

	mu      sync.Mutex
	session *verifiedSession
}

// NewClient creates a confidential Gateway client. wire must reject redirects
// and place GuardEHBPResponses around its network transport.
func NewClient(endpoint string, verifier evidenceVerifier, wire *http.Client) (*Client, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, errors.New("attestation verifier is required")
	}
	if wire == nil {
		return nil, errors.New("wire HTTP client is required")
	}
	if wire.CheckRedirect == nil {
		return nil, errors.New("wire HTTP client must reject redirects")
	}
	return &Client{
		endpoint: endpoint,
		verifier: verifier,
		wire:     wire,
		now:      time.Now,
	}, nil
}

// WithLedger records every verification attempt in the local verification
// ledger. The ledger receives evidence and metadata only, never request or
// response bodies.
func (c *Client) WithLedger(record *ledger.Ledger) *Client {
	c.ledger = record
	return c
}

func validateEndpoint(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid confidential Gateway endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" ||
		parsed.Path != attestation.ConfidentialEndpoint || parsed.RawPath != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("confidential Gateway endpoint must be an exact HTTPS URL ending in %s", attestation.ConfidentialEndpoint)
	}
	return nil
}

// WarmUp verifies the Gateway before a local listener starts accepting
// prompts.
func (c *Client) WarmUp(ctx context.Context) error {
	_, err := c.sessionFor(ctx)
	return err
}

// Do sends one JSON envelope. The Authorization header remains outside EHBP,
// matching the existing Gateway API. No request is automatically retried. The
// returned identifier names the attested key the body was encrypted to.
func (c *Client) Do(ctx context.Context, authorization, accept, userAgent string, envelope []byte) (*http.Response, string, error) {
	if len(envelope) == 0 {
		return nil, "", errors.New("confidential request envelope is empty")
	}
	session, err := c.sessionFor(ctx)
	if err != nil {
		return nil, "", err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(envelope))
	if err != nil {
		return nil, session.attestationID, fmt.Errorf("create confidential Gateway request: %w", err)
	}
	// EHBP v0.2.6 clones GetBody unchanged. Remove the plaintext replay closure
	// in addition to rejecting every redirect at both HTTP client layers.
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	} else {
		request.Header.Set("User-Agent", "nexus-proxy/1")
	}

	response, err := session.client.Do(request)
	if err != nil {
		if identity.IsKeyConfigError(err) {
			c.invalidate(session)
		}
		return nil, session.attestationID, fmt.Errorf("confidential Gateway exchange failed: %w", err)
	}
	return response, session.attestationID, nil
}

func (c *Client) sessionFor(ctx context.Context) (*verifiedSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil && c.now().Before(c.session.expiresAt) {
		return c.session, nil
	}

	evidence, err := c.verifier.Verify(ctx)
	if err != nil {
		c.ledger.RecordRejected(err.Error())
		return nil, fmt.Errorf("verify Gateway attestation: %w", err)
	}
	if evidence == nil || !c.now().Before(evidence.ExpiresAt) {
		const failure = "Gateway attestation has no remaining validity"
		c.ledger.RecordRejected(failure)
		return nil, errors.New(failure)
	}
	serverIdentity, err := identity.FromPublicKeyBytes(evidence.PublicKey)
	if err != nil {
		c.ledger.RecordRejected(err.Error())
		return nil, fmt.Errorf("use attested Gateway HPKE key: %w", err)
	}
	ehbpTransport, err := ehbpclient.NewTransportWithIdentity(
		serverIdentity,
		ehbpclient.WithHTTPClient(c.wire),
	)
	if err != nil {
		c.ledger.RecordRejected(err.Error())
		return nil, fmt.Errorf("create attested EHBP transport: %w", err)
	}

	attestationID := ledger.FingerprintKey(evidence.PublicKey)
	if c.ledger != nil {
		record, document, manifest := describeEvidence(attestationID, evidence, c.now().UTC())
		c.ledger.RecordVerified(record, document, manifest)
	}

	c.session = &verifiedSession{
		attestationID: attestationID,
		client: &http.Client{
			Transport: ehbpTransport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("confidential Gateway redirects are not allowed")
			},
		},
		expiresAt: evidence.ExpiresAt,
	}
	return c.session, nil
}

func (c *Client) invalidate(session *verifiedSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == session {
		c.session = nil
	}
}
