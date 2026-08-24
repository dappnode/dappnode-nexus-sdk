package catalog

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	client, err := NewClient(server.URL+ModelsEndpoint, &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestFetchReturnsTheCatalog(t *testing.T) {
	const body = `{"object":"list","data":[{"id":"deepseek/deepseek-v4-flash"}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ModelsEndpoint {
			t.Errorf("path = %q, want %q", r.URL.Path, ModelsEndpoint)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("  " + body + "\n"))
	}))
	defer server.Close()

	status, got, err := newTestClient(t, server).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if string(got) != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

// The catalog needs no credential, and the Gateway ignores one. Forwarding a
// local client's Nexus API key would push it onto a path that terminates at
// Cloudflare for no benefit at all.
func TestFetchSendsNoCredential(t *testing.T) {
	var seen http.Header
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer server.Close()

	if _, _, err := newTestClient(t, server).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"} {
		if value := seen.Get(header); value != "" {
			t.Fatalf("%s was forwarded upstream: %q", header, value)
		}
	}
}

// An intermediary that returns an HTML error page must not reach a local
// client that was told the response is JSON.
func TestFetchRejectsANonJSONBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>Cloudflare</body></html>"))
	}))
	defer server.Close()

	status, body, err := newTestClient(t, server).Fetch(context.Background())
	if err == nil {
		t.Fatal("expected an error for an HTML body")
	}
	if body != nil {
		t.Fatalf("body = %q, want nil", body)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
}

func TestFetchRejectsAJSONArray(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id":"a"}]`))
	}))
	defer server.Close()

	if _, _, err := newTestClient(t, server).Fetch(context.Background()); err == nil {
		t.Fatal("expected an error for a bare JSON array")
	}
}

func TestFetchRejectsAnOversizeBody(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":"` + strings.Repeat("a", maxCatalogBytes) + `"}`))
	}))
	defer server.Close()

	if _, _, err := newTestClient(t, server).Fetch(context.Background()); err == nil {
		t.Fatal("expected an error for an oversize catalog")
	}
}

func TestNewClientRejectsUnsafeEndpoints(t *testing.T) {
	wire := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
	for _, endpoint := range []string{
		"",
		"http://nexus-api-tee.dappnode.com/v1/models",
		"https://nexus-api-tee.dappnode.com",
		"https://nexus-api-tee.dappnode.com/v1/chat/completions",
		"https://nexus-api-tee.dappnode.com/v1/confidential/chat/completions",
		"https://nexus-api-tee.dappnode.com/v1/models?filter=all",
		"https://user:pass@nexus-api-tee.dappnode.com/v1/models",
		"https://nexus-api-tee.dappnode.com/v1/models#fragment",
	} {
		if _, err := NewClient(endpoint, wire); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
}

func TestNewClientRequiresARedirectRejectingClient(t *testing.T) {
	const endpoint = "https://nexus-api-tee.dappnode.com/v1/models"
	if _, err := NewClient(endpoint, nil); err == nil {
		t.Fatal("accepted a nil HTTP client")
	}
	if _, err := NewClient(endpoint, &http.Client{}); err == nil {
		t.Fatal("accepted an HTTP client that follows redirects")
	}
}
