package nexus_test

import (
	"context"
	"net/http"

	nexus "github.com/dappnode/dappnode-nexus-sdk"
)

// These assignments compile from an external package and guard the embeddable
// API from accidentally depending on an internal Go package.
var (
	_ func(context.Context, nexus.Config) (*nexus.Client, error)                   = nexus.New
	_ func(*nexus.Client) http.Handler                                             = (*nexus.Client).Handler
	_ func(*nexus.Client) *http.Client                                             = (*nexus.Client).HTTPClient
	_ func(*nexus.Client, context.Context, string, []byte) (*http.Response, error) = (*nexus.Client).ChatCompletions
	_ func(*nexus.Client, context.Context) (*http.Response, error)                 = (*nexus.Client).Models
	_ func(*nexus.Client, context.Context) (*nexus.Attestation, error)             = (*nexus.Client).Verify
	_ func(*nexus.Client) nexus.Snapshot                                           = (*nexus.Client).Verification
	_ func(*nexus.Client, string) (*nexus.Evidence, error)                         = (*nexus.Client).Evidence
	_ func(*nexus.Client) error                                                    = (*nexus.Client).Close
)
