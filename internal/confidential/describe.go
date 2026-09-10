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
				Detail: "Signed by the TEE's hardware security module (AWS Nitro), module " + proof.ModuleID + ". Only real hardware can produce this signature.",
			},
			{
				Name:   "AWS certificate chain",
				Passed: true,
				Detail: "The signing certificate chains to the AWS Nitro root CA, SHA-256 " + short(proof.RootFingerprint) + ".",
			},
			{
				Name:   "Freshness: this proxy's nonce",
				Passed: true,
				Detail: "The TEE signed the random 32-byte challenge this proxy generated, so the evidence cannot be a replay of an older attestation.",
			},
			{
				Name:   "Fresh proof",
				Passed: true,
				Detail: signedAgo(age) + ". Proofs older than " + humanDuration(evidence.ExpiresAt.Sub(evidence.AttestedAt)) + " are refused, so an old one can't be reused.",
			},
			{
				Name:   "Code measurements PCR0, PCR1, PCR2",
				Passed: true,
				Detail: "The measurements of the software running in the TEE match, byte for byte, the ones Dappnode signed for this Gateway release. Different code produces different measurements.",
			},
			{
				Name:   "Signed workload manifest",
				Passed: true,
				Detail: "The TEE's signed user_data equals SHA-384 of its manifest, so the manifest below is covered by the hardware signature.",
			},
			{
				Name:   "Gateway source revision",
				Passed: true,
				Detail: "The manifest declares source revision " + proof.SourceRevision + ", which is the revision this proxy is willing to trust.",
			},
			{
				Name:   "Encryption contract",
				Passed: true,
				Detail: fmt.Sprintf("The manifest declares %s over %s on %s, with both request and response bodies encrypted.", proof.E2EE.Protocol, proof.E2EE.Suite, proof.E2EE.Endpoint),
			},
			{
				Name:   "Key binding",
				Passed: true,
				Detail: "The X25519 public key your request bodies are encrypted to is carried inside the signed document. Its private half exists only inside the TEE, so nothing in between can read them.",
			},
		},
	}
	return record, proof.Document, proof.Manifest
}

// signedAgo describes how old the proof was when it was checked. The proxy asks
// for a new proof right before checking it, so this is nearly always under a
// second; printing "0s" there read like a bug.
func signedAgo(age time.Duration) string {
	if age < 5*time.Second {
		return "Signed just now"
	}
	return "Signed " + humanDuration(age) + " before it was checked"
}

// humanDuration formats whole seconds or minutes, avoiding forms like "2m0s".
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d >= time.Minute && d%time.Minute == 0 {
		if m := int(d / time.Minute); m == 1 {
			return "1 minute"
		} else {
			return fmt.Sprintf("%d minutes", m)
		}
	}
	return fmt.Sprintf("%d seconds", int(d/time.Second))
}

func short(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:16] + "…"
}
