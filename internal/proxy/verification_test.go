package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/confidential"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

// provenVerifier returns evidence carrying the same proof material a real
// Nitro verification retains.
type provenVerifier struct{ key []byte }

func (v *provenVerifier) Verify(context.Context) (*attestation.Evidence, error) {
	return &attestation.Evidence{
		PublicKey:  append([]byte(nil), v.key...),
		AttestedAt: time.Now().Add(-time.Second),
		ExpiresAt:  time.Now().Add(time.Minute),
		Proof: attestation.Proof{
			Document: []byte("COSE-SIGN1-DOCUMENT-BYTES"),
			Manifest: json.RawMessage(`{"schema_version":4,"workload":"dappnode-nexus-gateway"}`),
			Nonce:    []byte("0123456789abcdef0123456789abcdef"),
			ModuleID: "i-0abc-enc0123456789",
			PCRs: map[uint][]byte{
				0: []byte("pcr0-measurement"),
				1: []byte("pcr1-measurement"),
				2: []byte("pcr2-measurement"),
			},
			RootFingerprint: "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b",
			SourceRevision:  "b9afcee715ee35700b6ff1fc94445c75c191a1d1",
			Workload:        attestation.GatewayWorkload,
			Profile:         attestation.GatewayProfile,
			E2EE: attestation.E2EEPolicy{
				Protocol: attestation.EHBPProtocol, Suite: attestation.EHBPSuite,
				Endpoint: attestation.ConfidentialEndpoint, RequestEncrypted: true, ResponseEncrypted: true,
			},
		},
	}, nil
}

func newVerifiedProxy(t *testing.T, gatewayURL string, key []byte, wireTransport http.RoundTripper) (*httptest.Server, *ledger.Ledger) {
	t.Helper()
	wireClient := &http.Client{
		Transport: confidential.GuardEHBPResponses(wireTransport),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
	client, err := confidential.NewClient(gatewayURL+attestation.ConfidentialEndpoint, &provenVerifier{key: key}, wireClient)
	if err != nil {
		t.Fatal(err)
	}
	record := ledger.New()
	handler, err := NewHandler(client.WithLedger(record), nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler.WithVerification(record, "https://gateway.example"))
	t.Cleanup(server.Close)
	return server, record
}

func fetchBody(t *testing.T, url string) (int, string) {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

// TestVerificationLedgerNeverExposesBodies is the load-bearing test for the
// verification surface: it must describe the protection without ever holding
// the protected content.
func TestVerificationLedgerNeverExposesBodies(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-test","choices":[{"message":{"content":"`+completionCanary+`"}}]}`)
	})
	gateway, _ := newCapturedEHBPServer(t, serverIdentity, application)
	local, _ := newVerifiedProxy(t, gateway.URL, serverIdentity.MarshalPublicKey(), gateway.Client().Transport)

	requestBody := `{"model":"test","messages":[{"role":"user","content":"` + promptCanary + `"}]}`
	response, err := http.Post(local.URL+LocalChatEndpoint, "application/json", strings.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()

	status, snapshot := fetchBody(t, local.URL+LocalVerificationAPI)
	if status != http.StatusOK {
		t.Fatalf("verification API status = %d, want 200", status)
	}
	for _, canary := range []string{promptCanary, completionCanary, "messages", "content"} {
		if strings.Contains(snapshot, canary) {
			t.Fatalf("verification snapshot leaked %q:\n%s", canary, snapshot)
		}
	}

	var view struct {
		Status  string `json:"status"`
		Gateway string `json:"gateway"`
		Current *struct {
			ID       string `json:"id"`
			ModuleID string `json:"module_id"`
			Checks   []struct {
				Name   string `json:"name"`
				Passed bool   `json:"passed"`
			} `json:"checks"`
		} `json:"current"`
		Requests []struct {
			ID            string `json:"id"`
			Outcome       string `json:"outcome"`
			AttestationID string `json:"attestation_id"`
			RequestBytes  int    `json:"request_bytes"`
			ResponseBytes int64  `json:"response_bytes"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(snapshot), &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != ledger.OutcomeVerified {
		t.Fatalf("status = %q, want verified", view.Status)
	}
	if view.Current == nil || view.Current.ModuleID != "i-0abc-enc0123456789" {
		t.Fatalf("current attestation = %+v", view.Current)
	}
	if len(view.Current.Checks) == 0 {
		t.Fatal("current attestation has no checks")
	}
	for _, check := range view.Current.Checks {
		if !check.Passed {
			t.Fatalf("check %q did not pass", check.Name)
		}
	}
	if len(view.Requests) != 1 {
		t.Fatalf("recorded %d requests, want 1", len(view.Requests))
	}
	recorded := view.Requests[0]
	if recorded.Outcome != ledger.OutcomeEncrypted {
		t.Fatalf("request outcome = %q, want encrypted", recorded.Outcome)
	}
	if recorded.AttestationID != view.Current.ID {
		t.Fatalf("request attestation %q is not linked to current %q", recorded.AttestationID, view.Current.ID)
	}
	if recorded.RequestBytes != len(requestBody) || recorded.ResponseBytes == 0 {
		t.Fatalf("request sizes = %d/%d", recorded.RequestBytes, recorded.ResponseBytes)
	}
	if !canonicalUUID.MatchString(recorded.ID) {
		t.Fatalf("request ID %q is not the envelope UUID", recorded.ID)
	}
}

func TestVerificationDocumentIsServedVerbatim(t *testing.T) {
	serverIdentity, err := identity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	record := ledger.New()
	client, err := confidential.NewClient(
		"https://gateway.example"+attestation.ConfidentialEndpoint,
		&provenVerifier{key: serverIdentity.MarshalPublicKey()},
		&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("no") }},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WithLedger(record).WarmUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(client, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(handler.WithVerification(record, "https://gateway.example"))
	t.Cleanup(local.Close)

	id := ledger.FingerprintKey(serverIdentity.MarshalPublicKey())
	status, document := fetchBody(t, local.URL+LocalVerificationDocument+"?id="+id)
	if status != http.StatusOK || document != "COSE-SIGN1-DOCUMENT-BYTES" {
		t.Fatalf("document status = %d, body = %q", status, document)
	}
	status, manifest := fetchBody(t, local.URL+LocalVerificationDocument+"?id="+id+"&part=manifest")
	if status != http.StatusOK || !strings.Contains(manifest, "dappnode-nexus-gateway") {
		t.Fatalf("manifest status = %d, body = %q", status, manifest)
	}
	if status, _ := fetchBody(t, local.URL+LocalVerificationDocument+"?id=unknown"); status != http.StatusNotFound {
		t.Fatalf("unknown document status = %d, want 404", status)
	}
	if status, page := fetchBody(t, local.URL+LocalVerificationUI); status != http.StatusOK || !strings.Contains(page, "<html") {
		t.Fatalf("UI status = %d", status)
	}
}

func TestVerificationSurfaceAbsentWithoutLedger(t *testing.T) {
	handler, err := NewHandler(&healthTestSender{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(handler)
	t.Cleanup(local.Close)

	for _, path := range []string{LocalVerificationUI, LocalVerificationAPI, LocalVerificationDocument} {
		if status, _ := fetchBody(t, local.URL+path); status != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, status)
		}
	}
}

func TestRejectedAttestationIsRecordedAndBlocksRequests(t *testing.T) {
	record := ledger.New()
	record.RecordRejected("attestation PCR0 does not match the pinned measurement")

	snapshot := record.Snapshot()
	if snapshot.Status != ledger.OutcomeRejected {
		t.Fatalf("status = %q, want rejected", snapshot.Status)
	}
	if snapshot.Current != nil {
		t.Fatal("a rejected ledger must expose no current attestation")
	}
	if len(snapshot.Attestations) != 1 || !strings.Contains(snapshot.Attestations[0].Failure, "PCR0") {
		t.Fatalf("attestations = %+v", snapshot.Attestations)
	}
}
