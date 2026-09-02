# DAppNode Nexus SDK

A local, OpenAI-compatible client that verifies the Nexus Gateway before any
prompt is sent.

The SDK runs on your computer or server. At startup it checks a fresh
attestation from the Nexus Gateway running in a trusted execution environment
against a policy published by DAppNode. It accepts requests only after that
verification succeeds, then protects prompt and response bodies between the
local SDK and the verified Gateway.

You do not need a DAppNode to use it.

## Install

Go 1.26.8 or newer is required.

```sh
go install github.com/dappnode/dappnode-nexus-sdk/cmd/nexus-proxy@latest
```

Alternatively, build it from source:

```sh
git clone https://github.com/dappnode/dappnode-nexus-sdk.git
cd dappnode-nexus-sdk
make build
```

## Download the Nexus trust policy

The maintained policy in this repository identifies the Nexus Gateway
releases the SDK is allowed to trust. Download it through the DAppNode GitHub
organization rather than from the Gateway being verified:

```sh
curl -fsSLo nexus-gateway-policy.json \
  https://raw.githubusercontent.com/dappnode/dappnode-nexus-sdk/main/nexus-gateway-policy.json
```

Keep this file updated when DAppNode publishes support for a new Gateway
release.

## Start the SDK

```sh
nexus-proxy \
  --gateway-url https://nexus-api-tee.dappnode.com \
  --trust-policy ./nexus-gateway-policy.json
```

The SDK verifies the Gateway before opening its local listener. If verification
fails, it exits without accepting prompts.

## Connect an application

Create an API key at [nexus.dappnode.com](https://nexus.dappnode.com), then
configure any OpenAI-compatible application with:

```text
Base URL: http://127.0.0.1:3301/v1
API key:  your Nexus API key
API:      OpenAI Chat Completions
```

For example:

```sh
export NEXUS_API_KEY="your-api-key"
export NEXUS_BASE_URL="http://127.0.0.1:3301/v1"

curl "$NEXUS_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $NEXUS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_ID","messages":[{"role":"user","content":"Hello"}]}'
```

Use `GET /v1/models` to list available model IDs. Regular and streaming chat
responses are supported.

## Verify the connection

Open the local verification page after starting the SDK:

```text
http://127.0.0.1:3301/verification
```

It shows whether the Gateway passed verification and which verified connection
handled each recent request. The page contains verification evidence and
request metadata, never prompts or responses.

## Embed the SDK in Go

Go applications can use the same verification and encrypted transport without
starting a separate process or opening a local port. For example, with the
[official OpenAI Go client](https://github.com/openai/openai-go):

```go
verifyCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

sdk, err := nexus.New(verifyCtx, nexus.Config{
    GatewayURL:      "https://nexus-api-tee.dappnode.com",
    TrustPolicyFile: "./nexus-gateway-policy.json",
})
cancel()
if err != nil {
    log.Fatal(err)
}
defer sdk.Close()

client := openai.NewClient(
    option.WithAPIKey(os.Getenv("NEXUS_API_KEY")),
    option.WithBaseURL(nexus.InProcessBaseURL),
    option.WithHTTPClient(sdk.HTTPClient()),
)
completion, err := client.Chat.Completions.New(context.Background(), openai.ChatCompletionNewParams{
    Messages: []openai.ChatCompletionMessageParamUnion{
        openai.UserMessage("Hello"),
    },
    Model: "MODEL_ID",
})
if err != nil {
    log.Fatal(err)
}
fmt.Println(completion.Choices[0].Message.Content)
```

`New` returns only after the Gateway passes verification. Developers can then:

- Mount `Handler()` in an existing Go HTTP server.
- Give `HTTPClient()` and `nexus.InProcessBaseURL` to another Go SDK without
  opening a local port.
- Call `ChatCompletions()` or `Models()` directly.
- Call `Verify()`, `Verification()`, and `Evidence()` to build their own
  verification experience or independently inspect the signed evidence.
- Call `Close()` before exit when using a persistent `StateFile`.

`TrustPolicyJSON` can be used with Go's `embed` package when the application
should carry its pinned policy inside the binary.

See the complete [embedding example](examples/embed/main.go) and the
[package documentation](https://pkg.go.dev/github.com/dappnode/dappnode-nexus-sdk).

## Using it on DAppNode

DAppNode users can install **Nexus Local Proxy** instead of running the binary
manually. Applications on the same DAppNode then use:

```text
http://nexus-local-proxy.dappnode.private:3301/v1
```

## What is protected

- The SDK verifies the Gateway before accepting prompts.
- Prompt and response bodies are encrypted between the SDK and the verified
  Gateway.
- Prompt and response content is not written to verification history or logs.

The machine running the SDK remains trusted. Request metadata, including
headers, sizes, and timing, is outside the body-encryption boundary. Protection
also does not extend beyond Nexus to a downstream model provider. Keep the
local listener private to your machine or trusted network.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development instructions. Report
security issues as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). Dependency notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
