# DAppNode Nexus SDK

`nexus-proxy` is an OpenAI-compatible proxy for the confidential Nexus
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
  "schema_version": 2,
  "manifest_schema_version": 4,
  "workload": "dappnode-nexus-gateway",
  "profile": "nexus-gateway-v2",
  "releases": [
    {
      "source_revision": "REPLACE_WITH_40_LOWERCASE_HEX_CHARACTERS",
      "pcr0": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS",
      "pcr1": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS",
      "pcr2": "REPLACE_WITH_96_LOWERCASE_HEX_CHARACTERS"
    }
  ],
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

### Pinning more than one release

`releases` accepts up to four entries so a Gateway can be rolled out without
every client failing closed in the interval before it is updated. Publish a
policy listing both the outgoing and the incoming release, let clients pick it
up, deploy the new Gateway, then publish a policy listing only the new release.

Each entry is matched as a whole. The verifier selects the single entry whose
`source_revision` the signed manifest claims, and accepts only that entry's
measurements; it never accepts a measurement from one entry alongside a
revision from another. Evidence naming a revision that is not pinned is
rejected outright.

Keep the list short. Every entry is a build you are asserting is trustworthy,
so remove a release as soon as nothing is running it.

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

For a shared Nexus Proxy package on a trusted DAppNode, use the explicit
DAppNode listener scope:

```sh
./bin/nexus-proxy \
  --gateway-url https://nexus-api-tee.dappnode.com \
  --trust-policy ./nexus-gateway-policy.json \
  --listen 0.0.0.0:3301 \
  --listen-scope dappnode
```

The DAppNode package must not publish this port outside the trusted DAppNode
environment. `GET /healthz` reports local process readiness; because the HTTP
listener is created only after startup attestation succeeds, an available
health endpoint also means startup verification completed successfully.

## Privacy verification page

`GET /verification` serves a local page that reports whether the Gateway is
currently verified, which checks passed, and which attested key each request
was encrypted to. `GET /v1/verification` returns the same data as JSON, and
`GET /v1/verification/document?id=ID` returns the raw COSE_Sign1 attestation
document (add `&part=manifest` for the signed manifest) so the evidence can be
re-checked with an independent AWS Nitro verifier.

The page is rendered by the same process that performs the verification, so it
cannot prove itself; its purpose is to surface the signed evidence and hand it
back for independent checking.

The ledger behind it holds verification evidence, which is public by
construction, plus per request identifiers, timing and sizes. It never receives
prompt or completion content, and nothing is written to disk: history is kept in
memory unless `--state-file` is given. Pass `--verification-ui=false` to
remove the page and its API entirely.

`--state-file PATH` persists verification history so it survives a restart.
Only evidence and metadata are written — the signed attestation documents, the
manifests they commit to, and per request identifiers, timing, sizes and
outcome. The on-disk format has no field that could hold a prompt or a
completion. The file is written `0600`, replaced atomically, and flushed off
the request path; a missing or unreadable file starts an empty history rather
than blocking startup. Without the flag the ledger stays memory-only, exactly
as before.

Point an OpenAI-compatible client at `http://127.0.0.1:3301/v1` and keep using
its normal API-key setting. For example:

```sh
curl http://127.0.0.1:3301/v1/chat/completions \
  -H 'Authorization: Bearer YOUR_NEXUS_API_KEY' \
  -H 'Content-Type: application/json' \
  -d '{"model":"MODEL","messages":[{"role":"user","content":"hello"}]}'
```

`GET /v1/models` returns the Gateway's model catalog, so a client that
enumerates models against its base URL works without extra configuration.

Both ordinary JSON responses and `stream: true` SSE responses are supported.
The proxy never automatically retries an inference request. After an explicit
stale-key failure it discards the cached key; a new caller request triggers new
attestation. Deployments therefore require one active enclave per Gateway
origin or key-affine routing.

## Model catalog

`GET /v1/models` passes the Gateway's public model catalog through unchanged.
This is **not** a confidential path, and it is the one route on this proxy that
is not covered by the guarantee above:

- The catalog is public, unauthenticated, cacheable data. It carries no prompt,
  no completion and no credential, so there is nothing to encrypt.
- It is fetched over ordinary TLS, not over EHBP, and the Gateway serves it at
  the standard `/v1/models` path rather than the confidential endpoint.
- The caller's `Authorization` header is **not** forwarded. The Gateway ignores
  it, and forwarding it would put a Nexus API key on a path that terminates at
  Cloudflare for no benefit.
- The response is released only when it is one complete JSON object, so an HTML
  error page from an intermediary cannot reach a client expecting JSON.
- These requests are not recorded in the verification ledger. Counting them
  would overstate how many bodies actually crossed the attested channel.

Pass `--model-catalog=false` to remove the route entirely and leave the
confidential inference endpoint as the only upstream this proxy talks to.

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
downstream inference providers. In DAppNode listener mode, callers also trust
the DAppNode host and its internal network: the caller-to-proxy hop is ordinary
HTTP and is outside the EHBP boundary.

The proxy rejects redirects, plaintext confidential responses, malformed or
oversized frames, oversized non-streaming bodies, stale evidence, key
substitution, and attestation downgrades. It logs neither API keys nor
request/response bodies.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency licenses.
