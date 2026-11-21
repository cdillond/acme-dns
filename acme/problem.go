package acme

import (
	"encoding/json/v2"
	"fmt"
)

type Problem struct {
	Type        ProblemType  `json:"type,omitempty"`
	Title       string       `json:"title,omitempty"`
	Status      int64        `json:"status,omitzero"`
	Detail      string       `json:"detail,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	Subproblems []Subproblem `json:"subproblems,omitempty"`
}

type Subproblem struct {
	Type       ProblemType `json:"type,omitempty"`
	Detail     string      `json:"detail,omitempty"`
	Identifier Identifier  `json:"identifier,omitzero"`
}

func (p *Problem) Error() string {
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("%#v", *p)
	}
	return string(b)
}

// ProblemType is an ACME error type URI as defined in RFC 8555 Section 6.7.
type ProblemType string

const (
	ProblemTypeAccountDoesNotExist     ProblemType = "urn:ietf:params:acme:error:accountDoesNotExist"
	ProblemTypeAlreadyRevoked          ProblemType = "urn:ietf:params:acme:error:alreadyRevoked"
	ProblemTypeBadCSR                  ProblemType = "urn:ietf:params:acme:error:badCSR"
	ProblemTypeBadNonce                ProblemType = "urn:ietf:params:acme:error:badNonce"
	ProblemTypeBadPublicKey            ProblemType = "urn:ietf:params:acme:error:badPublicKey"
	ProblemTypeBadRevocationReason     ProblemType = "urn:ietf:params:acme:error:badRevocationReason"
	ProblemTypeBadSignatureAlgorithm   ProblemType = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ProblemTypeCAA                     ProblemType = "urn:ietf:params:acme:error:caa"
	ProblemTypeCompound                ProblemType = "urn:ietf:params:acme:error:compound"
	ProblemTypeConnection              ProblemType = "urn:ietf:params:acme:error:connection"
	ProblemTypeDNS                     ProblemType = "urn:ietf:params:acme:error:dns"
	ProblemTypeExternalAccountRequired ProblemType = "urn:ietf:params:acme:error:externalAccountRequired"
	ProblemTypeIncorrectResponse       ProblemType = "urn:ietf:params:acme:error:incorrectResponse"
	ProblemTypeInvalidContact          ProblemType = "urn:ietf:params:acme:error:invalidContact"
	ProblemTypeMalformed               ProblemType = "urn:ietf:params:acme:error:malformed"
	ProblemTypeOrderNotReady           ProblemType = "urn:ietf:params:acme:error:orderNotReady"
	ProblemTypeRateLimited             ProblemType = "urn:ietf:params:acme:error:rateLimited"
	ProblemTypeRejectedIdentifier      ProblemType = "urn:ietf:params:acme:error:rejectedIdentifier"
	ProblemTypeServerInternal          ProblemType = "urn:ietf:params:acme:error:serverInternal"
	ProblemTypeTLS                     ProblemType = "urn:ietf:params:acme:error:tls"
	ProblemTypeUnauthorized            ProblemType = "urn:ietf:params:acme:error:unauthorized"
	ProblemTypeUnsupportedContact      ProblemType = "urn:ietf:params:acme:error:unsupportedContact"
	ProblemTypeUnsupportedIdentifier   ProblemType = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ProblemTypeUserActionRequired      ProblemType = "urn:ietf:params:acme:error:userActionRequired"
)

// Description returns the RFC 8555 Section 6.7 description for the problem type.
// If the problem type is not one of the standard types defined in RFC 8555, it
// returns an empty string.
func (p ProblemType) Description() string {
	switch p {
	case ProblemTypeAccountDoesNotExist:
		return "The request specified an account that does not exist"
	case ProblemTypeAlreadyRevoked:
		return "The request specified a certificate to be revoked that has already been revoked"
	case ProblemTypeBadCSR:
		return "The CSR is unacceptable (e.g., due to a short key)"
	case ProblemTypeBadNonce:
		return "The client sent an unacceptable anti-replay nonce"
	case ProblemTypeBadPublicKey:
		return "The JWS was signed by a public key the server does not support"
	case ProblemTypeBadRevocationReason:
		return "The revocation reason provided is not allowed by the server"
	case ProblemTypeBadSignatureAlgorithm:
		return "The JWS was signed with an algorithm the server does not support"
	case ProblemTypeCAA:
		return "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate"
	case ProblemTypeCompound:
		return "Specific error conditions are indicated in the \"subproblems\" array"
	case ProblemTypeConnection:
		return "The server could not connect to validation target"
	case ProblemTypeDNS:
		return "There was a problem with a DNS query during identifier validation"
	case ProblemTypeExternalAccountRequired:
		return "The request must include a value for the \"externalAccountBinding\" field"
	case ProblemTypeIncorrectResponse:
		return "Response received didn't match the challenge's requirements"
	case ProblemTypeInvalidContact:
		return "A contact URL for an account was invalid"
	case ProblemTypeMalformed:
		return "The request message was malformed"
	case ProblemTypeOrderNotReady:
		return "The request attempted to finalize an order that is not ready to be finalized"
	case ProblemTypeRateLimited:
		return "The request exceeds a rate limit"
	case ProblemTypeRejectedIdentifier:
		return "The server will not issue certificates for the identifier"
	case ProblemTypeServerInternal:
		return "The server experienced an internal error"
	case ProblemTypeTLS:
		return "The server received a TLS error during validation"
	case ProblemTypeUnauthorized:
		return "The client lacks sufficient authorization"
	case ProblemTypeUnsupportedContact:
		return "A contact URL for an account used an unsupported protocol scheme"
	case ProblemTypeUnsupportedIdentifier:
		return "An identifier is of an unsupported type"
	case ProblemTypeUserActionRequired:
		return "Visit the \"instance\" URL and take actions specified there"
	default:
		return ""
	}
}
