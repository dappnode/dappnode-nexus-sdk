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
