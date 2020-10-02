package jwit

import "errors"

// Signer errors
var (
	// ErrUnknownKeyType indicates that the provided public/private key type is unknown.
	ErrUnknownKeyType = errors.New("jwit: provided public/private key type is unknown")
)

// Verifier errors
var (
	// ErrUnknownIssuer indicates that token is not issued by a known issuer.
	ErrUnknownIssuer = errors.New("jwit: the JWT issuer is unknown")

	// ErrUnexpectedSignature indicates that none of the issuer's JWK was used to sign the token.
	ErrUnexpectedSignature = errors.New("jwit: the JWT wasn't signed with a known signature")

	// ErrJWKSFetchFailed indicates that we got a non-2xx HTTP status whil fetching the JWKS.
	ErrJWKSFetchFailed = errors.New("jwit: couldn't fetch JWKS from server")
)
