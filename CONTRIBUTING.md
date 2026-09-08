# Contributing

Thanks for helping improve the DAppNode Nexus SDK.

## Development setup

Install Go 1.26.8 or newer, clone the repository, and run the standard checks:

```sh
make test
make vet
make build
```

The compiled binary is written to `bin/nexus-proxy`.

## Project layout

- The root `nexus` package is the stable API for applications embedding the
  SDK.
- `cmd/nexus-proxy` contains the executable.
- `internal/attestation` verifies the Nexus Gateway.
- `internal/confidential` protects request and response bodies.
- `internal/proxy` provides the local OpenAI-compatible API.
- `internal/ledger` powers the local verification history.

## Pull requests

Keep changes focused, add or update tests for behavior changes, and make sure
`make test`, `make vet`, and `make build` pass before opening a pull request.

The policy in `nexus-gateway-policy.json` is updated only from verified Gateway
release measurements. Deployment and release runbooks are maintained privately
by the DAppNode team and are intentionally not part of this public repository.

## Regenerating the embedded Sigstore trusted root

`internal/release/trusted_root.json` is the Sigstore trusted root the SDK
verifies signed Gateway releases against. It is embedded rather than fetched so
the decision about which signing authority to believe stays inside the measured
binary, and so an offline client can still verify.

Refresh it when preparing a release:

```sh
cosign trusted-root create > internal/release/trusted_root.json
```

Then run `go test ./internal/release/` — the fixtures under
`internal/release/testdata/` are real published release assets, so they fail if
the regenerated root cannot verify a genuine signature.
