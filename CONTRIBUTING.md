# Contributing

Thanks for helping improve the Nexus Privacy Layer.

## Development setup

Install Go 1.26.8 or newer, clone the repository, and run the standard checks:

```sh
make test
make vet
make build
```

The compiled binary is written to `bin/nexus-proxy`.

## Project layout

- `cmd/nexus-proxy` contains the executable.
- `internal/attestation` verifies the confidential Nexus service.
- `internal/confidential` protects request and response bodies.
- `internal/proxy` provides the local OpenAI-compatible API.
- `internal/ledger` powers the local verification history.

## Pull requests

Keep changes focused, add or update tests for behavior changes, and make sure
`make test`, `make vet`, and `make build` pass before opening a pull request.

Operational policies, release measurements, and deployment runbooks are
maintained privately by the DAppNode team and are intentionally not part of
this public repository.
