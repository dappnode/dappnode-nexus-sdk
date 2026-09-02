package nexus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

func TestValidateConfig(t *testing.T) {
	gatewayURL, timeout, err := validateConfig(Config{
		GatewayURL:      "https://gateway.example/",
		TrustPolicyFile: "/tmp/policy.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gatewayURL != "https://gateway.example" {
		t.Fatalf("Gateway URL = %q", gatewayURL)
	}
	if timeout != defaultAttestationTimeout {
		t.Fatalf("timeout = %v", timeout)
	}

	tests := []Config{
		{TrustPolicyFile: "/tmp/policy.json"},
		{GatewayURL: "http://gateway.example", TrustPolicyFile: "/tmp/policy.json"},
		{GatewayURL: "https://gateway.example/path", TrustPolicyFile: "/tmp/policy.json"},
		{GatewayURL: "https://gateway.example"},
		{GatewayURL: "https://gateway.example", TrustPolicyFile: "/tmp/policy.json", TrustPolicyJSON: []byte(`{}`)},
		{GatewayURL: "https://gateway.example", TrustPolicyFile: "/tmp/policy.json", AttestationTimeout: -time.Second},
	}
	for _, config := range tests {
		if _, _, err := validateConfig(config); err == nil {
			t.Fatalf("validateConfig(%+v) succeeded", config)
		}
	}
}

func TestHTTPClientUsesHandlerWithoutNetwork(t *testing.T) {
	sdk := &Client{handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != ModelsPath {
			t.Errorf("path = %q", request.URL.Path)
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(response, `{"object":"list"}`)
	})}

	response, err := sdk.HTTPClient().Get(InProcessBaseURL + "/models")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusAccepted || string(body) != `{"object":"list"}` {
		t.Fatalf("response = %d %q", response.StatusCode, body)
	}
}

func TestHTTPClientRejectsOtherOrigins(t *testing.T) {
	sdk := &Client{handler: http.NotFoundHandler()}
	_, err := sdk.HTTPClient().Get("https://example.com/v1/models")
	if err == nil || !strings.Contains(err.Error(), InProcessBaseURL) {
		t.Fatalf("HTTPClient error = %v", err)
	}
}

func TestHTTPClientReturnsHandlerPanic(t *testing.T) {
	sdk := &Client{handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})}
	_, err := sdk.HTTPClient().Get(InProcessBaseURL + "/models")
	if err == nil || !strings.Contains(err.Error(), "embedded Nexus handler panic") {
		t.Fatalf("HTTPClient error = %v", err)
	}
}

func TestChatCompletionsBuildsOpenAIRequest(t *testing.T) {
	type observation struct {
		method        string
		path          string
		authorization string
		contentType   string
		body          []byte
	}
	observed := make(chan observation, 1)
	sdk := &Client{handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observed <- observation{
			method:        request.Method,
			path:          request.URL.Path,
			authorization: request.Header.Get("Authorization"),
			contentType:   request.Header.Get("Content-Type"),
			body:          body,
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, `{"choices":[]}`)
	})}

	payload := []byte(`{"model":"test","messages":[]}`)
	response, err := sdk.ChatCompletions(context.Background(), "secret", payload)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	got := <-observed
	if got.method != http.MethodPost || got.path != ChatCompletionsPath ||
		got.authorization != "Bearer secret" || got.contentType != "application/json" ||
		!bytes.Equal(got.body, payload) {
		t.Fatalf("request = %+v", got)
	}
}

func TestHTTPClientStreamsHandlerResponse(t *testing.T) {
	sdk := &Client{handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "text/event-stream")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "data: first\n\n")
		response.(http.Flusher).Flush()
		_, _ = io.WriteString(response, "data: [DONE]\n\n")
	})}

	response, err := sdk.HTTPClient().Get(InProcessBaseURL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "data: first\n\ndata: [DONE]\n\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestVerificationAndEvidenceArePublicCopies(t *testing.T) {
	record := ledger.Attestation{
		ID:         "attestation-id",
		VerifiedAt: time.Now().UTC(),
		Checks:     []ledger.Check{{Name: "signature", Passed: true, Detail: "valid"}},
	}
	document := []byte("signed-document")
	manifest := json.RawMessage(`{"schema_version":4}`)
	history := ledger.New()
	history.RecordVerified(record, document, manifest)
	sdk := &Client{ledger: history}

	snapshot := sdk.Verification()
	if snapshot.Current == nil || snapshot.Current.ID != record.ID || len(snapshot.Current.Checks) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	evidence, err := sdk.Evidence(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(evidence.Document, document) || !bytes.Equal(evidence.Manifest, manifest) {
		t.Fatalf("evidence = %+v", evidence)
	}
	evidence.Document[0] = 'X'
	again, err := sdk.Evidence(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(evidence.Document, again.Document) {
		t.Fatal("Evidence returned shared document storage")
	}
	if _, err := sdk.Evidence("missing"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("missing evidence error = %v", err)
	}
}

func TestChatCompletionsRejectsInvalidInputs(t *testing.T) {
	sdk := &Client{handler: http.NotFoundHandler()}
	for name, test := range map[string]struct {
		key  string
		body []byte
	}{
		"missing key":  {body: []byte(`{}`)},
		"invalid JSON": {key: "secret-value", body: []byte(`{`)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sdk.ChatCompletions(context.Background(), test.key, test.body)
			if err == nil {
				t.Fatal("ChatCompletions succeeded with invalid input")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
