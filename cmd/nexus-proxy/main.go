package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	nexus "github.com/dappnode/dappnode-nexus-sdk"
)

const (
	defaultListenAddress  = "127.0.0.1:3301"
	defaultRequestTimeout = 15 * time.Second
	shutdownTimeout       = 10 * time.Second
	stateFlushInterval    = 5 * time.Second
	listenScopeLoopback   = "loopback"
	listenScopeDAppNode   = "dappnode"
)

type config struct {
	gatewayOrigin      string
	trustPolicyPath    string
	listenAddress      string
	listenScope        string
	attestationTimeout time.Duration
	verificationUI     bool
	modelCatalog       bool
	stateFile          string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	configuration, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	logger := log.New(stderr, "nexus-proxy: ", log.LstdFlags|log.LUTC)
	warmupContext, cancelWarmup := context.WithTimeout(context.Background(), configuration.attestationTimeout)
	sdk, err := nexus.New(warmupContext, nexus.Config{
		GatewayURL:            configuration.gatewayOrigin,
		TrustPolicyFile:       configuration.trustPolicyPath,
		AttestationTimeout:    configuration.attestationTimeout,
		StateFile:             configuration.stateFile,
		DisableVerificationUI: !configuration.verificationUI,
		DisableModelCatalog:   !configuration.modelCatalog,
		Logger:                logger,
	})
	cancelWarmup()
	if err != nil {
		logger.Printf("initialize Nexus SDK: %v", err)
		return 1
	}
	defer func() {
		if err := sdk.Close(); err != nil {
			logger.Printf("persist verification history on exit: %v", err)
		}
	}()
	if configuration.listenScope == listenScopeDAppNode {
		logger.Printf("DAppNode network listener enabled on %s; do not publish this port outside the trusted DAppNode environment", configuration.listenAddress)
	}
	listener, err := net.Listen("tcp", configuration.listenAddress)
	if err != nil {
		logger.Printf("listen on %s: %v", configuration.listenAddress, err)
		return 1
	}
	defer listener.Close()

	server := &http.Server{
		Handler:           sdk.Handler(),
		ErrorLog:          logger,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()
	logger.Printf("verified Gateway and listening on http://%s", listener.Addr())
	if configuration.verificationUI {
		logger.Printf("privacy verification UI at http://%s%s", listener.Addr(), nexus.VerificationPath)
	}
	if configuration.modelCatalog {
		logger.Printf("public model catalog at http://%s%s; it is served over ordinary TLS, not the attested channel", listener.Addr(), nexus.ModelsPath)
	}

	// Verification history is written behind the request path, never on it: a
	// slow disk must not delay an inference response. Everything written is
	// evidence and metadata, never a prompt or a completion.
	stopFlushing := make(chan struct{})
	if configuration.stateFile != "" {
		logger.Printf("persisting verification history to %s", configuration.stateFile)
		go func() {
			ticker := time.NewTicker(stateFlushInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := sdk.Flush(); err != nil {
						logger.Printf("persist verification history: %v", err)
					}
				case <-stopFlushing:
					return
				}
			}
		}()
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)

	select {
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("local proxy failed: %v", err)
			return 1
		}
		return 0
	case received := <-signals:
		logger.Printf("received %s; shutting down", received)
	}

	close(stopFlushing)
	if err := sdk.Flush(); err != nil {
		logger.Printf("persist verification history on shutdown: %v", err)
	}

	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
		return 1
	}
	if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("local proxy failed during shutdown: %v", err)
		return 1
	}
	return 0
}

func parseFlags(args []string, stderr io.Writer) (*config, error) {
	flags := flag.NewFlagSet("nexus-proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: nexus-proxy --gateway-url URL --trust-policy FILE [options]\n")
		flags.PrintDefaults()
	}

	gatewayURL := flags.String("gateway-url", "", "Nexus Gateway HTTPS origin")
	trustPolicy := flags.String("trust-policy", "", "client-pinned trust policy JSON file")
	listen := flags.String("listen", defaultListenAddress, "numeric listen address")
	listenScope := flags.String("listen-scope", listenScopeLoopback, "listener scope: loopback or dappnode")
	attestationTimeout := flags.Duration("attestation-timeout", defaultRequestTimeout, "attestation HTTP timeout")
	verificationUI := flags.Bool("verification-ui", true, "serve the local privacy verification page and its JSON API")
	modelCatalog := flags.Bool("model-catalog", true, "serve GET /v1/models by passing the Gateway's public model catalog through over ordinary TLS")
	stateFile := flags.String("state-file", "", "persist verification history to this file; empty keeps it in memory only")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, errors.New("unexpected positional arguments")
	}
	origin, err := validateGatewayOrigin(*gatewayURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(*trustPolicy) == "" {
		return nil, errors.New("--trust-policy is required")
	}
	if err := validateListenAddress(*listen, *listenScope); err != nil {
		return nil, err
	}
	if *attestationTimeout <= 0 {
		return nil, errors.New("--attestation-timeout must be positive")
	}
	return &config{
		gatewayOrigin:      origin,
		trustPolicyPath:    *trustPolicy,
		listenAddress:      *listen,
		listenScope:        *listenScope,
		attestationTimeout: *attestationTimeout,
		verificationUI:     *verificationUI,
		modelCatalog:       *modelCatalog,
		stateFile:          *stateFile,
	}, nil
}

func validateGatewayOrigin(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--gateway-url is required")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return "", fmt.Errorf("invalid --gateway-url: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.Opaque != "" {
		return "", errors.New("--gateway-url must be an absolute HTTPS origin")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawPath != "" {
		return "", errors.New("--gateway-url must not contain credentials, a query, or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("--gateway-url must be an origin without a path")
	}
	return (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String(), nil
}

func validateListenAddress(address, scope string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid --listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("--listen must use a numeric IP address")
	}
	switch scope {
	case listenScopeLoopback:
		if !ip.IsLoopback() {
			return errors.New("--listen-scope loopback requires a loopback address such as 127.0.0.1:3301 or [::1]:3301")
		}
	case listenScopeDAppNode:
		if !ip.IsUnspecified() {
			return errors.New("--listen-scope dappnode requires 0.0.0.0 or [::]")
		}
	default:
		return errors.New("--listen-scope must be loopback or dappnode")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return errors.New("--listen must specify a non-zero port")
	}
	return nil
}
