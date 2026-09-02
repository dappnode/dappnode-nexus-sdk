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
