package jwit

import (
	"crypto"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// Verifier can verify a JWT validity. Don't create verifiers directly, use jwit.NewVerifier*
// helpers instead.
type Verifier struct {
	// Issuers a set of trusted issuers, mapped by name (corresponding to the "iss" claim).
	Issuers map[string]*Issuer

	// The HTTP client used to fetch issuer's JWKS. By default, doesn't follow any redirections.
	HttpClient *http.Client
}

// New creates a new JWIT Verifier given a set of truster issuers.
func NewVerifier(issuers ...*Issuer) (*Verifier, error) {
	httpClient := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	issuersMap := make(map[string]*Issuer, len(issuers))
	for _, issuer := range issuers {
		if err := issuer.initialize(); err != nil {
			return nil, err
		}
		issuersMap[issuer.Name] = issuer
	}

	return &Verifier{
		Issuers:    issuersMap,
		HttpClient: &httpClient,
	}, nil
}

// validateToken checks if any of the known keys was used to sign the provided token. If so,
// returns true and unmarshals it into dest (if not nil).
func (verifier *Verifier) validateToken(
	token *jwt.JSONWebToken,
	jwks *jose.JSONWebKeySet,
	dest ...interface{},
) (bool, error) {
	var claims jwt.Claims

	// Try to find a key with the proper KID.
	// go-jose already does this, but if no key match fails with "ErrUnsupportedKeyType".
	// What we want instead is try the keys we know.
	kid := getKeyID(token)
	if kid != "" {
		for _, jwk := range jwks.Keys {
			if jwk.KeyID == kid {
				// We found a key with token's KID.
				jwks = &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{jwk},
				}
				break
			}
		}
	}

	// Check the token against each known keys.
	// Note that we do not need to randomize the keys order to prevent timing attacks because
	// we're checking against a public key set anyways.
	var matchingKey *jose.JSONWebKey
	for _, jwk := range jwks.Keys {
		if err := token.Claims(jwk.Key, &claims); err == nil {
			matchingKey = &jwk
			break
		}
	}

	if matchingKey == nil {
		return false, ErrUnexpectedSignature
	}

	// Check the token's registered claims (exp, nbf, …).
	if err := claims.Validate(jwt.Expected{
		Time: time.Now(),
	}); err != nil {
		return false, err
	}

	// We know the token is valid and was signed using a key that is known from the issuer.
	// Is is safe to unserialize the token as its claims were already checked in validateToken.
	for _, d := range dest {
		if err := token.UnsafeClaimsWithoutVerification(d); err != nil {
			return false, err
		}
	}

	// Token is valid.
	return true, nil
}

// VerifyJWTWithKeys verifies whether the provided raw JWT is valid and was signed using any of the
// provided public keys. If the JWT is valid (i.e. comes from a known issuer, was signed by any
// of the provided public keys and is under its validity period), true is returned. If it
// is valid and dest is non-nil, the JWT claims are unmarshalled into dest.
func (verifier *Verifier) VerifyJWTWithKeys(
	rawJWT string,
	publicKeys []crypto.PublicKey,
	dest ...interface{},
) (bool, error) {
	token, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return false, err
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(publicKeys)),
	}
	for i, publicKey := range publicKeys {
		jwks.Keys[i].Key = publicKey
	}

	return verifier.validateToken(token, &jwks, dest...)
}

// VerifyJWT verifies whether the provided raw JWT is valid and was signed using any of the public
// keys that are known from the JWT issuer. If the JWT is valid (i.e. comes from a known issuer, was
// signed by any of the known issuer's public keys and is under its validity period), true is returned.
// If it is valid and dest is non-nil, the JWT claims are unmarshalled into dest.
// If the JWT doesn't come from a known issuer, ErrUnknownIssuer is returned.
func (verifier *Verifier) VerifyJWT(rawJWT string, dest ...interface{}) (bool, error) {
	token, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		return false, err
	}

	var issuerClaim struct {
		UnsafeIssuerName string `json:"iss"`
	}
	// Get the JWT pretended issuer.
	if err := token.UnsafeClaimsWithoutVerification(&issuerClaim); err != nil {
		return false, ErrUnknownIssuer
	}
	unsafeIssuerName := issuerClaim.UnsafeIssuerName

	// Find the corresponding issuer.
	issuer, issuerIsKnown := verifier.Issuers[unsafeIssuerName]
	if !issuerIsKnown {
		return false, ErrUnknownIssuer
	}

	// Get the JWKS we know from this issuer.
	issuerJWKS, err := issuer.getJWKS(verifier.HttpClient)
	if err != nil {
		return false, err
	}

	// Validate the JWT against the known-safe public keys.
	return verifier.validateToken(token, issuerJWKS, dest...)
}

// getKeyID returns the kid header of a JSON Web Token, or "" if it's not set.
func getKeyID(token *jwt.JSONWebToken) string {
	for _, header := range token.Headers {
		if header.KeyID != "" {
			return header.KeyID
		}
	}

	return ""
}
