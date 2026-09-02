// Package nexus provides attestation-verified, OpenAI-compatible access to the
// DAppNode Nexus Gateway.
//
// New verifies the Gateway before it returns a Client. Applications can mount
// Client.Handler in an existing HTTP server, give Client.HTTPClient to another
// Go SDK, or call Client.ChatCompletions directly.
package nexus
