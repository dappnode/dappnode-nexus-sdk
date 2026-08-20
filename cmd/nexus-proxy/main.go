package main

import (
	"context"
	"crypto/tls"
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

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/confidential"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
	"github.com/dappnode/dappnode-nexus-sdk/internal/proxy"
)

const (
	defaultListenAddress  = "127.0.0.1:3301"
	defaultRequestTimeout = 15 * time.Second
	shutdownTimeout       = 10 * time.Second
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
	policy, err := attestation.LoadPolicy(configuration.trustPolicyPath)
	if err != nil {
		logger.Printf("load trust policy: %v", err)
		return 1
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	wireClient := &http.Client{
		Transport: confidential.GuardEHBPResponses(transport),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
	attestationClient := &http.Client{
		Transport: transport,
		Timeout:   configuration.attestationTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}

	verifier, err := attestation.NewVerifier(
		configuration.gatewayOrigin+"/v1/attestation",
		policy,
		attestationClient,
	)
	if err != nil {
		logger.Printf("configure attestation verifier: %v", err)
		return 1
	}
	confidentialClient, err := confidential.NewClient(
		configuration.gatewayOrigin+attestation.ConfidentialEndpoint,
		verifier,
		wireClient,
	)
	if err != nil {
		logger.Printf("configure confidential Gateway client: %v", err)
		return 1
	}
	var verificationLedger *ledger.Ledger
	if configuration.verificationUI {
		verificationLedger = ledger.New()
		confidentialClient = confidentialClient.WithLedger(verificationLedger)
	}

	warmupContext, cancelWarmup := context.WithTimeout(context.Background(), configuration.attestationTimeout)
	err = confidentialClient.WarmUp(warmupContext)
	cancelWarmup()
	if err != nil {
		logger.Printf("initial Gateway attestation failed: %v", err)
		return 1
	}

	handler, err := proxy.NewHandler(confidentialClient, logger)
	if err != nil {
		logger.Printf("configure local proxy: %v", err)
		return 1
	}
	if verificationLedger != nil {
		handler = handler.WithVerification(verificationLedger, configuration.gatewayOrigin)
	}
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
		Handler:           handler,
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
	if verificationLedger != nil {
		logger.Printf("privacy verification UI at http://%s%s", listener.Addr(), proxy.LocalVerificationUI)
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
