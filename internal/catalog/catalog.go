// Package catalog fetches the Gateway's public model catalog.
//
// This is deliberately NOT a confidential path. GET /v1/models is an
// unauthenticated, publicly cacheable listing of the models the Gateway
// offers: it carries no prompt, no completion and no credential. It is
// therefore fetched over ordinary TLS rather than over EHBP, and the caller's
// Authorization header is never forwarded, so a local client's Nexus API key
// stays inside the proxy.
package catalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/dappnode/dappnode-nexus-sdk/internal/jsonutil"
)

// ModelsEndpoint is the Gateway path that serves the public model catalog.
// The Gateway serves inference at /v1/confidential/chat/completions but keeps
// the catalog on the standard OpenAI path.
const ModelsEndpoint = "/v1/models"

// maxCatalogBytes bounds an upstream that misbehaves. The live catalog is a
// few tens of kilobytes.
const maxCatalogBytes = 4 << 20

// Client reads the Gateway model catalog over plain HTTPS.
type Client struct {
	endpoint string
	wire     *http.Client
}

// NewClient creates a catalog client. wire must reject redirects so a
// redirect cannot move the request to another host.
func NewClient(endpoint string, wire *http.Client) (*Client, error) {
	if err := validateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if wire == nil {
		return nil, errors.New("wire HTTP client is required")
	}
	if wire.CheckRedirect == nil {
		return nil, errors.New("wire HTTP client must reject redirects")
	}
	return &Client{endpoint: endpoint, wire: wire}, nil
}

func validateEndpoint(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("invalid model catalog endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" ||
		parsed.Path != ModelsEndpoint || parsed.RawPath != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("model catalog endpoint must be an exact HTTPS URL ending in %s", ModelsEndpoint)
	}
	return nil
}

// Fetch returns the upstream status code and body. It sends no credential.
// The body is returned verbatim only when it is one complete JSON object, so
// an HTML error page from an intermediary can never reach a local client that
// was told to expect JSON.
func (c *Client) Fetch(ctx context.Context) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("build model catalog request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := c.wire.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("fetch model catalog: %w", err)
	}
	defer response.Body.Close()

	body, err := jsonutil.ReadAllLimited(response.Body, maxCatalogBytes)
	if err != nil {
		return response.StatusCode, nil, fmt.Errorf("read model catalog: %w", err)
	}
	body = bytes.TrimSpace(body)
	if !jsonutil.IsJSONObject(body) {
		return response.StatusCode, nil, errors.New("model catalog response was not one complete JSON object")
	}
	return response.StatusCode, body, nil
}
