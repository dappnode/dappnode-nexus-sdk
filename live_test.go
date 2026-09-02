package nexus_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	nexus "github.com/dappnode/dappnode-nexus-sdk"
)

func TestLiveAttestation(t *testing.T) {
	if os.Getenv("NEXUS_LIVE_TEST") != "1" {
		t.Skip("set NEXUS_LIVE_TEST=1 to run against the live Gateway")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	sdk := newLiveClient(t, ctx)

	verification := sdk.Verification()
	if verification.Current == nil || verification.Current.Outcome != nexus.OutcomeVerified {
		t.Fatalf("initial verification status = %q", verification.Status)
	}
	evidence, err := sdk.Evidence(verification.Current.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence.Document) == 0 || !json.Valid(evidence.Manifest) {
		t.Fatal("live verification did not retain valid signed evidence")
	}
	refreshed, err := sdk.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Outcome != nexus.OutcomeVerified || sdk.Verification().VerifiedTotal < 2 {
		t.Fatal("explicit re-verification did not record fresh evidence")
	}
}

func TestLiveGatewayCompletion(t *testing.T) {
	if os.Getenv("NEXUS_LIVE_TEST") != "1" {
		t.Skip("set NEXUS_LIVE_TEST=1 to run against the live Gateway")
	}
	apiKey := os.Getenv("NEXUS_API_KEY")
	if apiKey == "" {
		t.Fatal("NEXUS_API_KEY is required for the live completion test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	sdk := newLiveClient(t, ctx)

	modelsResponse, err := sdk.Models(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer modelsResponse.Body.Close()
	modelsBody, err := io.ReadAll(io.LimitReader(modelsResponse.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	model := os.Getenv("NEXUS_MODEL")
	if modelsResponse.StatusCode == http.StatusOK {
		var catalog struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(modelsBody, &catalog); err != nil || len(catalog.Data) == 0 || catalog.Data[0].ID == "" {
			t.Fatalf("model catalog was not a non-empty OpenAI model list: %v", err)
		}
		if model == "" {
			model = catalog.Data[0].ID
		}
	} else {
		if model == "" {
			model = "nexus/auto"
		}
		t.Logf("model catalog returned HTTP %d; trying %q", modelsResponse.StatusCode, model)
	}

	payload, err := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{{
			"role":    "user",
			"content": "Reply only with OK.",
		}},
		"max_tokens": 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	completionResponse, err := sdk.ChatCompletions(ctx, apiKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer completionResponse.Body.Close()
	completionBody, err := io.ReadAll(io.LimitReader(completionResponse.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	if completionResponse.StatusCode != http.StatusOK {
		var gatewayError struct {
			Error struct {
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		_ = json.Unmarshal(completionBody, &gatewayError)
		t.Fatalf("chat completion returned HTTP %d (%s: %s)", completionResponse.StatusCode, gatewayError.Error.Type, gatewayError.Error.Message)
	}
	var completion struct {
		Choices []json.RawMessage `json:"choices"`
	}
	if err := json.Unmarshal(completionBody, &completion); err != nil || len(completion.Choices) == 0 {
		t.Fatalf("chat completion was not a valid OpenAI response: %v", err)
	}
}

func newLiveClient(t *testing.T, ctx context.Context) *nexus.Client {
	t.Helper()
	policyFile := os.Getenv("NEXUS_POLICY_FILE")
	if policyFile == "" {
		policyFile = "nexus-gateway-policy.json"
	}
	gatewayURL := os.Getenv("NEXUS_GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "https://nexus-api-tee.dappnode.com"
	}

	sdk, err := nexus.New(ctx, nexus.Config{
		GatewayURL:      gatewayURL,
		TrustPolicyFile: policyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sdk.Close(); err != nil {
			t.Errorf("close SDK: %v", err)
		}
	})
	return sdk
}
