.PHONY: build test vet

build:
	go build -trimpath -o bin/nexus-proxy ./cmd/nexus-proxy

test:
	go test ./...

vet:
	go vet ./...
