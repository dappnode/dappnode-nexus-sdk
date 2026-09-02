# Nexus Privacy Layer

Private, OpenAI-compatible access to Nexus for applications running on
DAppNode.

The Nexus Privacy Layer runs locally on your DAppNode. It verifies the Nexus
confidential service before accepting traffic, then protects prompt and
response bodies on their way to and from Nexus. Applications keep using the
standard OpenAI API format.

This repository contains the privacy component used by the **Nexus Local
Proxy** DAppNode package. Most users should install the package rather than
build this repository directly.

## Connect an application

1. Install **Nexus Local Proxy** on your DAppNode.
2. Create an API key at [nexus.dappnode.com](https://nexus.dappnode.com).
3. Configure an application on the same DAppNode with:

```text
Base URL: http://nexus-local-proxy.dappnode.private:3301/v1
API key:  your Nexus API key
API:      OpenAI Chat Completions
```

For example:

```sh
export NEXUS_API_KEY="your-api-key"
export NEXUS_BASE_URL="http://nexus-local-proxy.dappnode.private:3301/v1"

curl "$NEXUS_BASE_URL/chat/completions" \
  -H "Authorization: Bearer $NEXUS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"MODEL_ID","messages":[{"role":"user","content":"Hello"}]}'
```

Use `GET /v1/models` to find the model IDs available to your account. Both
regular responses and streaming responses are supported.

## Check your privacy connection

Open the local verification page after installing the package:

```text
http://nexus-local-proxy.dappnode.private:3301/verification
```

It shows whether the Nexus service passed verification and which protected
connection handled each recent request. The page contains verification
evidence and request metadata, never prompts or responses.

## What is protected

- Prompt and response bodies are encrypted between this local privacy layer
  and the verified Nexus confidential service.
- The service refuses to start if it cannot verify the confidential service.
- Prompt and response content is not written to the verification history or
  application logs.

The DAppNode host and its internal network remain trusted. Request metadata,
including headers, sizes, and timing, is outside the body-encryption boundary.
The protection also does not extend beyond Nexus to a downstream model
provider. Do not expose the local service port to the public Internet.

## For contributors

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow. Please
report security issues as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE). Dependency notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
