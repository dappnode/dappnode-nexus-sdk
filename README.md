# DAppNode Nexus SDK

`nexus-proxy` is a host-only OpenAI-compatible proxy for the confidential Nexus
Gateway endpoint. It verifies fresh AWS Nitro attestation against a policy you
pin, takes the Gateway's X25519 key only from that signed attestation, and then
uses EHBP to encrypt request and response bodies through intermediaries such as
Cloudflare.

The proxy does not use a Tinfoil service or EHBP's network key-discovery
endpoint. EHBP is linked as an ordinary MIT-licensed Go library.

## Build

Go 1.26.4 or newer is required.

```sh
make test
make vet
make build
```

## Trust policy

Obtain the source revision and PCR0/PCR1/PCR2 measurements from a Nexus Gateway
release through a channel you trust. Do not copy measurements from the Gateway
being verified.

```json
{
  "schema_version": 1,
  "manifest_schema_version": 4,
  "workload": "dappnode-nexus-gateway",
  "profile": "nexus-gateway-v2",
  "source_revision": "REPLACE_WITH_40_LOWERCASE_HEX_CHARACTERS",
  "pcr0": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS",
  "pcr1": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS",
  "pcr2": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS",
  "e2ee": {
    "protocol": "ehbp-v1",
    "suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-256-GCM",
    "endpoint": "/v1/confidential/chat/completions",
    "request_encrypted": true,
    "response_encrypted": true
  }
}
```

The parser rejects unknown fields, all-zero debug PCRs, non-canonical values,
and any unsupported E2EE contract.

## Run

```sh
./bin/nexus-proxy \
  --gateway-url https://nexus-api-tee.dappnode.com \
  --trust-policy ./nexus-gateway-policy.json \
  --listen 127.0.0.1:3301
```

The listener must be a literal loopback IP. Startup fails unless the Gateway
produces fresh, nonce-bound evidence that passes the AWS certificate-chain,
COSE signature, timestamp, exact PCR, signed-manifest digest, pinned manifest
claims, and public-key checks.

Point an OpenAI-compatible client at `http://127.0.0.1:3301/v1` and keep using
its normal API-key setting. For example:

```sh
curl http://127.0.0.1:3301/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_NEXUS_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"MODEL","messages":[{"role":"user","content":"hello"}]}'
```

Both ordinary JSON responses and `stream: true` SSE responses are supported.
The proxy never automatically retries an inference request. After an explicit
stale-key failure it discards the cached key; a new caller request triggers new
attestation. Deployments therefore require one active enclave per Gateway
origin or key-affine routing.

## Security boundary

The verified claim is deliberately narrow: the JSON request body, including
the prompt, is encrypted and integrity-protected from this proxy to the
attested Nexus Gateway enclave; authenticated response frames are decrypted
only by this proxy. Normal JSON is fully read and validated before release.
Streaming frames are released after individual authentication, and the local
connection is aborted on decryption failure or if the authenticated stream
ends without `data: [DONE]`.

EHBP does **not** protect the HTTP method, URL, status, headers, body length,
frame sizes, or timing. In particular, `Authorization: Bearer ...` remains
visible to Cloudflare and is not cryptographically bound to the encrypted
body. Intermediaries can still drop traffic or alter visible metadata, but
cannot read or alter this proxy's encrypted prompt undetected, or make this
proxy accept an altered completion body. Because the EHBP public key and bearer
credential are visible, a TLS terminator can copy the API key and submit an
independent encrypted request; preventing that impersonation is outside v1.
The client machine and local proxy are trusted, and this claim does not cover
downstream inference providers.

The proxy rejects redirects, plaintext confidential responses, malformed or
oversized frames, oversized non-streaming bodies, stale evidence, key
substitution, and attestation downgrades. It logs neither API keys nor
request/response bodies.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency licenses.
