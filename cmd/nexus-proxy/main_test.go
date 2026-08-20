package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestValidateGatewayOrigin(t *testing.T) {
	valid := map[string]string{
		"https://gateway.example":      "https://gateway.example",
		"https://gateway.example/":     "https://gateway.example",
		"https://gateway.example:8443": "https://gateway.example:8443",
	}
	for input, expected := range valid {
		got, err := validateGatewayOrigin(input)
		if err != nil || got != expected {
			t.Fatalf("validateGatewayOrigin(%q) = %q, %v; want %q", input, got, err, expected)
		}
	}

	invalid := []string{
		"",
		"http://gateway.example",
		"https://user@gateway.example",
		"https://gateway.example/prefix",
		"https://gateway.example?query=value",
		"https://gateway.example#fragment",
		"gateway.example",
	}
	for _, input := range invalid {
		if _, err := validateGatewayOrigin(input); err == nil {
			t.Fatalf("validateGatewayOrigin(%q) succeeded", input)
		}
	}
}

func TestValidateListenAddress(t *testing.T) {
	for _, address := range []string{"127.0.0.1:3301", "127.10.20.30:443", "[::1]:3301"} {
		if err := validateListenAddress(address, listenScopeLoopback); err != nil {
			t.Fatalf("validateListenAddress(%q, loopback) error = %v", address, err)
		}
	}
	for _, address := range []string{
		"localhost:3301",
		"0.0.0.0:3301",
		"192.168.1.2:3301",
		"[::]:3301",
		"127.0.0.1:0",
		"127.0.0.1:http",
		"127.0.0.1:65536",
		"127.0.0.1",
	} {
		if err := validateListenAddress(address, listenScopeLoopback); err == nil {
			t.Fatalf("validateListenAddress(%q, loopback) succeeded", address)
		}
	}
	for _, address := range []string{"0.0.0.0:3301", "[::]:3301"} {
		if err := validateListenAddress(address, listenScopeDAppNode); err != nil {
			t.Fatalf("validateListenAddress(%q, dappnode) error = %v", address, err)
		}
	}
	for _, address := range []string{"127.0.0.1:3301", "192.168.1.2:3301", "localhost:3301"} {
		if err := validateListenAddress(address, listenScopeDAppNode); err == nil {
			t.Fatalf("validateListenAddress(%q, dappnode) succeeded", address)
		}
	}
	if err := validateListenAddress("127.0.0.1:3301", "public"); err == nil {
		t.Fatal("validateListenAddress accepted an unknown scope")
	}
}

func TestParseFlags(t *testing.T) {
	configuration, err := parseFlags([]string{
		"--gateway-url", "https://gateway.example/",
		"--trust-policy", "/tmp/policy.json",
		"--listen", "[::1]:4400",
		"--listen-scope", "loopback",
		"--attestation-timeout", "20s",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.gatewayOrigin != "https://gateway.example" ||
		configuration.trustPolicyPath != "/tmp/policy.json" ||
		configuration.listenAddress != "[::1]:4400" ||
		configuration.listenScope != listenScopeLoopback ||
		configuration.attestationTimeout != 20*time.Second {
		t.Fatalf("configuration = %+v", configuration)
	}
}

func TestParseFlagsRequiresSecurityInputs(t *testing.T) {
	tests := [][]string{
		{"--trust-policy", "/tmp/policy.json"},
		{"--gateway-url", "https://gateway.example"},
		{"--gateway-url", "https://gateway.example", "--trust-policy", "/tmp/policy.json", "--listen", "0.0.0.0:3301"},
		{"--gateway-url", "https://gateway.example", "--trust-policy", "/tmp/policy.json", "--listen", "127.0.0.1:3301", "--listen-scope", "dappnode"},
		{"--gateway-url", "https://gateway.example", "--trust-policy", "/tmp/policy.json", "--listen", "0.0.0.0:3301", "--listen-scope", "public"},
		{"--gateway-url", "https://gateway.example", "--trust-policy", "/tmp/policy.json", "--attestation-timeout", "0s"},
	}
	for _, args := range tests {
		_, err := parseFlags(args, &bytes.Buffer{})
		if err == nil {
			t.Fatalf("parseFlags(%q) succeeded", strings.Join(args, " "))
		}
	}
}

func TestParseFlagsDAppNodeListener(t *testing.T) {
	configuration, err := parseFlags([]string{
		"--gateway-url", "https://gateway.example",
		"--trust-policy", "/tmp/policy.json",
		"--listen", "0.0.0.0:3301",
		"--listen-scope", "dappnode",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.listenAddress != "0.0.0.0:3301" || configuration.listenScope != listenScopeDAppNode {
		t.Fatalf("configuration = %+v", configuration)
	}
}
