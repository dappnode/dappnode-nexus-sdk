package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

type stubCatalog struct {
	status int
	body   []byte
	err    error

	calls int
}

func (s *stubCatalog) Fetch(context.Context) (int, []byte, error) {
	s.calls++
	return s.status, s.body, s.err
}

func newCatalogHandler(t *testing.T, source catalogFetcher) (*Handler, *healthTestSender) {
	t.Helper()
	sender := &healthTestSender{}
	handler, err := NewHandler(sender, nil)
	if err != nil {
		t.Fatal(err)
	}
	if source != nil {
		handler = handler.WithModelCatalog(source)
	}
	return handler, sender
}

func TestModelsEndpointPassesTheCatalogThrough(t *testing.T) {
	source := &stubCatalog{status: http.StatusOK, body: []byte(`{"object":"list","data":[{"id":"deepseek/deepseek-v4-flash"}]}`)}
	handler, sender := newCatalogHandler(t, source)

	request := httptest.NewRequest(http.MethodGet, LocalModelsEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Body.String(); got != string(source.body) {
		t.Fatalf("body = %q, want %q", got, source.body)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if source.calls != 1 {
		t.Fatalf("catalog fetches = %d, want 1", source.calls)
	}
	if sender.called {
		t.Fatal("the model catalog was fetched over the confidential channel")
	}
}

// The catalog is public data fetched over ordinary TLS. Counting it as an
// encrypted request would overstate how many bodies actually crossed the
// attested channel, which is the one number the verification page exists to
// report honestly.
func TestModelsEndpointIsNotRecordedInTheLedger(t *testing.T) {
	record := ledger.New()
	source := &stubCatalog{status: http.StatusOK, body: []byte(`{"object":"list","data":[]}`)}
	handler, _ := newCatalogHandler(t, source)
	handler = handler.WithVerification(record, "https://nexus-api-tee.dappnode.com")

	for range 3 {
		request := httptest.NewRequest(http.MethodGet, LocalModelsEndpoint, nil)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	snapshot := record.Snapshot()
	if snapshot.EncryptedTotal != 0 || snapshot.FailedTotal != 0 {
		t.Fatalf("encrypted = %d, failed = %d, want 0 and 0", snapshot.EncryptedTotal, snapshot.FailedTotal)
	}
	if len(snapshot.Requests) != 0 {
		t.Fatalf("recorded %d requests, want 0", len(snapshot.Requests))
	}
}

func TestModelsEndpointFailsWhenTheGatewayCannotBeRead(t *testing.T) {
	source := &stubCatalog{err: errors.New("dial failed")}
	handler, _ := newCatalogHandler(t, source)

	request := httptest.NewRequest(http.MethodGet, LocalModelsEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	var decoded struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if decoded.Error.Type != "api_error" {
		t.Fatalf("error type = %q, want api_error", decoded.Error.Type)
	}
}

func TestModelsEndpointForwardsAnUpstreamErrorStatus(t *testing.T) {
	source := &stubCatalog{status: http.StatusServiceUnavailable, body: []byte(`{"error":{"message":"catalog unavailable"}}`)}
	handler, _ := newCatalogHandler(t, source)

	request := httptest.NewRequest(http.MethodGet, LocalModelsEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(response.Body.String(), "catalog unavailable") {
		t.Fatalf("body = %q", response.Body.String())
	}
}

func TestModelsEndpointRejectsOtherMethods(t *testing.T) {
	source := &stubCatalog{status: http.StatusOK, body: []byte(`{}`)}
	handler, _ := newCatalogHandler(t, source)

	request := httptest.NewRequest(http.MethodPost, LocalModelsEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q", response.Header().Get("Allow"))
	}
	if source.calls != 0 {
		t.Fatalf("catalog fetches = %d, want 0", source.calls)
	}
}

// --model-catalog=false must remove the route, not serve an empty list.
func TestModelsEndpointIsAbsentWithoutACatalog(t *testing.T) {
	handler, _ := newCatalogHandler(t, nil)

	request := httptest.NewRequest(http.MethodGet, LocalModelsEndpoint, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}
