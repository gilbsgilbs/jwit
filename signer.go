package jwit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// Signer will help you sign your JWTs and expose your public JWKS.
type Signer struct {
	DefaultClaims RegisteredClaims

	signingJWKS jose.JSONWebKeySet
	otherJWKS   jose.JSONWebKeySet

	joseSigners []jose.Signer
}

// RegisteredClaims as per RFC7919.
// See https://tools.ietf.org/html/rfc7519#section-4.1
type RegisteredClaims struct {
	// Duration is provided as an alternative to the Expiration Time ("exp") claim.
	Duration time.Duration

	Issuer    string    // iss
	Subject   string    // sub
	Audience  []string  // aud
	Expiry    time.Time // exp
	NotBefore time.Time // nbf
	IssuedAt  time.Time // iat
	ID        string    // jit
}

// C is a shortcut for RegisteredClaims.
type C = RegisteredClaims

// NewSigner creates a new signer from marshalled JWKS or PEM payloads. signingBytes are the JWKS
// or PEM private keys that will be used to sign the JWTs. otherBytes can contains public or private
// JWKs or PEMs that will be used in addition to signing keys to expose your public JWKS.
func NewSigner(signingKeysBytes []byte, otherKeysBytes ...[]byte) (*Signer, error) {
	if signingKeysBytes[0] == '{' {
		return NewSignerFromJWKS(signingKeysBytes, otherKeysBytes...)
	}

	return NewSignerFromPEM(signingKeysBytes, otherKeysBytes...)
}

// NewSignerFromJWKS creates a new signer from marshalled JWKS payloads. Signing JWKS are the
// JWKS that will be used to sign the JWTs. Other JWKS can contains public or private JWKs that
// will be used in addition to signing keys to expose your public JWKS.
func NewSignerFromJWKS(signingJWKSBytes []byte, otherJWKSBytes ...[]byte) (*Signer, error) {
	signingJWKS, err := loadJWKS(signingJWKSBytes)
	if err != nil {
		return nil, err
	}

	otherJWKS := jose.JSONWebKeySet{}
	for _, jwksBytes := range otherJWKSBytes {
		jwks, err := loadJWKS(jwksBytes)
		if err != nil {
			return nil, err
		}
		otherJWKS.Keys = append(otherJWKS.Keys, jwks.Keys...)
	}

	return newSignerFromGoJoseJWKS(signingJWKS, otherJWKS)
}

// NewSignerFromPEM creates a new signer from PEM-encoded data. Signing PEMs are the private keys
// that will be used to sign the JWTs. Other PEMs can contain public or private keys that will be
// used in addition to signing keys to expose your public JWKS.
func NewSignerFromPEM(signingPEMBytes []byte, otherPEMBytes ...[]byte) (*Signer, error) {
	signingJWKS, err := pemToJWKS(signingPEMBytes)
	if err != nil {
		return nil, err
	}

	var otherJWKS jose.JSONWebKeySet
	if 0 < len(otherPEMBytes) {
		otherPEMs := bytes.Join(otherPEMBytes, []byte("\n"))
		otherJWKS, err = pemToJWKS(otherPEMs)
		if err != nil {
			return nil, err
		}
	}

	return newSignerFromGoJoseJWKS(signingJWKS, otherJWKS)
}

// NewSignerFromCrytoKeys creates a new Signer from go crypto keys. Signing keys are private keys
// that will be picked at random to sign new JWTs. Other keys can be public or private keys and
// will be used in addition to signing keys to expose your public JWKS.
func NewSignerFromCryptoKeys(signingKeys []crypto.PrivateKey, otherKeys ...interface{}) (*Signer, error) {
	signingJWKS := jose.JSONWebKeySet{}
	for _, key := range signingKeys {
		signingJWKS.Keys = append(signingJWKS.Keys, jose.JSONWebKey{Key: key})
	}

	otherJWKS := jose.JSONWebKeySet{}
	for _, key := range otherKeys {
		otherJWKS.Keys = append(otherJWKS.Keys, jose.JSONWebKey{Key: key})
	}

	return newSignerFromGoJoseJWKS(signingJWKS, otherJWKS)
}

// newSignerFromGoJoseJWKS creates a new signer from go-jose JWKS keys. Signing JWKS are the JWKS that
// will be used to sign the JWTs. Other JWKS can contain public or private JWKs that will be used
// in addition to signing keys to expose your public JWKS.
func newSignerFromGoJoseJWKS(
	signingJWKS jose.JSONWebKeySet,
	otherJWKS jose.JSONWebKeySet,
) (*Signer, error) {
	signer := Signer{
		signingJWKS: signingJWKS,
		otherJWKS:   otherJWKS,
	}
	if err := signer.initJoseSigners(); err != nil {
		return nil, err
	}

	return &signer, nil
}

// initJoseSigners initializes the jose signers in this jwit signer.
func (signer *Signer) initJoseSigners() error {
	var err error

	for _, jwk := range signer.signingJWKS.Keys {
		alg := jose.SignatureAlgorithm(jwk.Algorithm)
		if jwk.Algorithm == "" {
			alg, err = recommendedAlgorithmForKey(jwk)
			if err != nil {
				return err
			}
		}

		signerOpts := (&jose.SignerOptions{}).WithType("JWT")
		if jwk.KeyID != "" {
			signerOpts = signerOpts.WithHeader(jose.HeaderKey("kid"), jwk.KeyID)
		}
		joseSigner, err := jose.NewSigner(
			jose.SigningKey{
				Algorithm: alg,
				Key:       jwk,
			},
			signerOpts,
		)
		if err != nil {
			return err
		}

		signer.joseSigners = append(signer.joseSigners, joseSigner)
	}

	return nil
}

// pickRandomJoseSigner picks a random jose signer.
func (signer *Signer) pickRandomJoseSigner() (jose.Signer, error) {
	if len(signer.joseSigners) <= 1 {
		return signer.joseSigners[0], nil
	}

	idx, err := rand.Int(
		rand.Reader,
		big.NewInt(int64(len(signer.joseSigners))),
	)
	if err != nil {
		return nil, err
	}

	return signer.joseSigners[idx.Int64()], nil
}

// DumpPublicJWKS returns the JWKS corresponding to the public keys of this signer.
// The return value of this function is safe to expose publicly (usually at /.well-known/jwks.json)
func (signer *Signer) DumpPublicJWKS() ([]byte, error) {
	keys := make([]jose.JSONWebKey, 0, len(signer.signingJWKS.Keys)+len(signer.otherJWKS.Keys))

	for _, jwk := range signer.signingJWKS.Keys {
		keys = append(keys, jwk.Public())
	}

	for _, jwk := range signer.otherJWKS.Keys {
		keys = append(keys, jwk.Public())
	}

	return dumpJWKS(jose.JSONWebKeySet{
		Keys: keys,
	})
}

// DumpSigningJWKS returns the signing JWKS for this signer.
//
// /!\ Do not make this key public /!\
func (signer *Signer) DumpSigningJWKS() ([]byte, error) {
	return dumpJWKS(signer.signingJWKS)
}

// DumpOtherJWKS returns the other JWKS for this signer.
//
// /!\ Do not make this key public /!\
func (signer *Signer) DumpOtherJWKS() ([]byte, error) {
	return dumpJWKS(signer.otherJWKS)
}

// registeredClaimsToGoJoseClaims converts JWIT RegisteredClaims to a go-jose Claims object.
func (signer *Signer) registeredClaimsToGoJoseClaims(rc *C) *jwt.Claims {
	expiry := rc.Expiry
	if rc.Duration != 0 {
		expiry = time.Now().Add(rc.Duration)
	}

	return &jwt.Claims{
		Issuer:    rc.Issuer,
		Subject:   rc.Subject,
		Audience:  rc.Audience,
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(rc.NotBefore),
		IssuedAt:  jwt.NewNumericDate(rc.IssuedAt),
		ID:        rc.ID,
	}
}

// SignJWT returns a signed JWT with one of signer's signing keys picked at random.
func (signer *Signer) SignJWT(registeredClaims C, privateClaims ...interface{}) (string, error) {
	defaultClaims := signer.registeredClaimsToGoJoseClaims(&signer.DefaultClaims)
	claims := signer.registeredClaimsToGoJoseClaims(&registeredClaims)

	joseSigner, err := signer.pickRandomJoseSigner()
	if err != nil {
		return "", err
	}

	builder := jwt.Signed(joseSigner).Claims(defaultClaims).Claims(claims)
	for _, pk := range privateClaims {
		builder = builder.Claims(pk)
	}

	return builder.CompactSerialize()
}

// recommendedAlgorithmForKey returns the recommended signature algorithm (as per RFC7518) that
// is compatible with the type of the provided JWK. If the type of the provided JWK is not
// supported or unknown, ErrUnknownKeyType is returned.
//
// See https://tools.ietf.org/html/rfc7518#section-3.1
func recommendedAlgorithmForKey(privateKey jose.JSONWebKey) (jose.SignatureAlgorithm, error) {
	switch privateKey.Key.(type) {
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		return jose.ES256, nil
	}

	return "", ErrUnknownKeyType
}
