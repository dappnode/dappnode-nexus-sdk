package confidential

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
)

type fixedEvidenceVerifier struct {
	key []byte
}

func (v *fixedEvidenceVerifier) Verify(context.Context) (*attestation.Evidence, error) {
	return &attestation.Evidence{PublicKey: v.key, ExpiresAt: time.Now().Add(time.Minute)}, nil
}

type inspectingRoundTripper struct {
	t      *testing.T
	calls  int
	canary []byte
}

func (t *inspectingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls++
	if request.URL.String() != "https://gateway.example/v1/confidential/chat/completions" {
		t.t.Errorf("wire URL = %s", request.URL)
	}
	if request.GetBody != nil {
		t.t.Error("wire request retained plaintext GetBody replay closure")
	}
	if request.RequestURI != "" {
		t.t.Errorf("wire RequestURI = %q", request.RequestURI)
	}
	if request.Header.Get("Authorization") != "Bearer visible" {
		t.t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
	}
	if request.Header.Get(protocol.EncapsulatedKeyHeader) == "" {
		t.t.Error("wire request lacks EHBP encapsulated key")
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.t.Errorf("read encrypted request: %v", err)
	}
	if bytes.Contains(body, t.canary) {
		t.t.Errorf("wire body leaked plaintext: %q", body)
	}
	return nil, errors.New("stop after wire inspection")
}

func TestDoUsesOnlyAttestedKeyAndRemovesPlaintextReplayClosure(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	canary := []byte("secret-prompt-canary")
	transport := &inspectingRoundTripper{t: t, canary: canary}
	wire := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
	client, err := NewClient(
		"https://gateway.example/v1/confidential/chat/completions",
		&fixedEvidenceVerifier{key: serverIdentity.MarshalPublicKey()},
		wire,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(context.Background(), "Bearer visible", "application/json", "test", canary)
	if err == nil || !strings.Contains(err.Error(), "wire inspection") {
		t.Fatalf("Do() error = %v", err)
	}
	if transport.calls != 1 {
		t.Fatalf("wire calls = %d, want 1", transport.calls)
	}
}

func TestConfidentialEndpointMustBeExactHTTPSURL(t *testing.T) {
	tests := []string{
		"",
		"http://gateway.example/v1/confidential/chat/completions",
		"https://user@gateway.example/v1/confidential/chat/completions",
		"https://gateway.example/v1/chat/completions",
		"https://gateway.example/v1/confidential/chat/completions?key=value",
		"https://gateway.example/v1/confidential/chat/completions#fragment",
	}
	for _, endpoint := range tests {
		t.Run(endpoint, func(t *testing.T) {
			if err := validateEndpoint(endpoint); err == nil {
				t.Fatalf("validateEndpoint(%q) succeeded", endpoint)
			}
		})
	}
	if err := validateEndpoint("https://gateway.example/v1/confidential/chat/completions"); err != nil {
		t.Fatalf("valid endpoint error = %v", err)
	}
}

func TestNewClientRequiresRedirectPolicy(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewClient(
		"https://gateway.example/v1/confidential/chat/completions",
		&fixedEvidenceVerifier{key: serverIdentity.MarshalPublicKey()},
		&http.Client{},
	)
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("NewClient() error = %v, want redirect policy error", err)
	}
}
