package confidential

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dappnode/dappnode-nexus-sdk/internal/attestation"
	"github.com/dappnode/dappnode-nexus-sdk/internal/ledger"
)

// describeEvidence turns verified evidence into the ledger record the local
// verification UI renders. Every check listed here is one the verifier already
// enforced: reaching this function at all means all of them passed, because
// Verify returns an error otherwise.
func describeEvidence(id string, evidence *attestation.Evidence, verifiedAt time.Time) (ledger.Attestation, []byte, json.RawMessage) {
	proof := evidence.Proof
	age := verifiedAt.Sub(evidence.AttestedAt).Round(time.Second)
	if age < 0 {
		age = 0
	}

	record := ledger.Attestation{
		ID:              id,
		VerifiedAt:      verifiedAt,
		AttestedAt:      evidence.AttestedAt.UTC(),
		ExpiresAt:       evidence.ExpiresAt.UTC(),
		ModuleID:        proof.ModuleID,
		HPKEPublicKey:   hex.EncodeToString(evidence.PublicKey),
		Nonce:           hex.EncodeToString(proof.Nonce),
		PCR0:            hex.EncodeToString(proof.PCRs[0]),
		PCR1:            hex.EncodeToString(proof.PCRs[1]),
		PCR2:            hex.EncodeToString(proof.PCRs[2]),
		SourceRevision:  proof.SourceRevision,
		Workload:        proof.Workload,
		Profile:         proof.Profile,
		RootFingerprint: proof.RootFingerprint,
		Checks: []ledger.Check{
			{
				Name:   "Hardware signature",
				Passed: true,
				Detail: "The evidence is signed by the AWS Nitro Security Module of enclave " + proof.ModuleID + ". Only real Nitro hardware can produce this signature.",
			},
			{
				Name:   "AWS certificate chain",
				Passed: true,
				Detail: "The signing certificate chains to the AWS Nitro root CA, SHA-256 " + short(proof.RootFingerprint) + ".",
			},
			{
				Name:   "Freshness: this proxy's nonce",
				Passed: true,
				Detail: "The enclave signed the random 32-byte challenge this proxy generated, so the evidence cannot be a replay of an older attestation.",
			},
			{
				Name:   "Freshness: signing time",
				Passed: true,
				Detail: fmt.Sprintf("Signed %s before this check. Evidence older than %s is rejected and re-fetched.", age, evidence.ExpiresAt.Sub(evidence.AttestedAt).Round(time.Second)),
			},
			{
				Name:   "Code measurements PCR0, PCR1, PCR2",
				Passed: true,
				Detail: "The measurements of the software running in the enclave match, byte for byte, the values pinned in this proxy's local trust policy. Different code produces different measurements.",
			},
			{
				Name:   "Signed workload manifest",
				Passed: true,
				Detail: "The enclave's signed user_data equals SHA-384 of its manifest, so the manifest below is covered by the hardware signature.",
			},
			{
				Name:   "Pinned Gateway source revision",
				Passed: true,
				Detail: "The manifest declares source revision " + proof.SourceRevision + ", matching the pinned policy.",
			},
			{
				Name:   "Encryption contract",
				Passed: true,
				Detail: fmt.Sprintf("The manifest declares %s over %s on %s, with both request and response bodies encrypted.", proof.E2EE.Protocol, proof.E2EE.Suite, proof.E2EE.Endpoint),
			},
			{
				Name:   "Key binding",
				Passed: true,
				Detail: "The X25519 public key your request bodies are encrypted to is carried inside the signed document. Its private half exists only inside this enclave, so nothing between here and the enclave can read them.",
			},
		},
	}
	return record, proof.Document, proof.Manifest
}

func short(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "…"
}
