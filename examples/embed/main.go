package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	nexus "github.com/dappnode/dappnode-nexus-sdk"
)

func main() {
	gatewayURL := flag.String("gateway-url", "https://nexus-api-tee.dappnode.com", "Nexus Gateway HTTPS origin")
	policyFile := flag.String("trust-policy", "nexus-gateway-policy.json", "DAppNode-published trust policy")
	listen := flag.String("listen", "127.0.0.1:3301", "local listen address")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	sdk, err := nexus.New(ctx, nexus.Config{
		GatewayURL:      *gatewayURL,
		TrustPolicyFile: *policyFile,
		Logger:          log.Default(),
	})
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	defer sdk.Close()

	server := &http.Server{
		Addr:              *listen,
		Handler:           sdk.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	log.Printf("verified Gateway and listening on http://%s", *listen)
	log.Fatal(server.ListenAndServe())
}
