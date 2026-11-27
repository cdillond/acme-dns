package acme

import "testing"

func TestProblemTypeDescription(t *testing.T) {
	// Keep this list in sync with the RFC 8555 problem types above.
	known := []ProblemType{
		ProblemTypeAccountDoesNotExist,
		ProblemTypeAlreadyRevoked,
		ProblemTypeBadCSR,
		ProblemTypeBadNonce,
		ProblemTypeBadPublicKey,
		ProblemTypeBadRevocationReason,
		ProblemTypeBadSignatureAlgorithm,
		ProblemTypeCAA,
		ProblemTypeCompound,
		ProblemTypeConnection,
		ProblemTypeDNS,
		ProblemTypeExternalAccountRequired,
		ProblemTypeIncorrectResponse,
		ProblemTypeInvalidContact,
		ProblemTypeMalformed,
		ProblemTypeOrderNotReady,
		ProblemTypeRateLimited,
		ProblemTypeRejectedIdentifier,
		ProblemTypeServerInternal,
		ProblemTypeTLS,
		ProblemTypeUnauthorized,
		ProblemTypeUnsupportedContact,
		ProblemTypeUnsupportedIdentifier,
		ProblemTypeUserActionRequired,
	}
	for _, p := range known {
		if got := p.Description(); got == "" {
			t.Errorf("%s has an empty description", p)
		}
	}

	if got := ProblemType("urn:example:custom").Description(); got != "" {
		t.Errorf("custom problem type description = %q, want empty", got)
	}
}
