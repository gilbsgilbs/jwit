package jwit_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"

	"github.com/gilbsgilbs/jwit"
	"gopkg.in/square/go-jose.v2/jwt"
)

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func TestVerifier(t *testing.T) {
	// create a signer with two signing keys
	issuer0Sk0 := generateECDSAKey(t)
	issuer0Sk1 := generateECDSAKey(t)
	signer0, err := jwit.NewSignerFromCryptoKeys([]crypto.PrivateKey{issuer0Sk0, issuer0Sk1})
	if err != nil {
		t.Fatal(err)
	}

	// create a signer with one signing key
	issuer1Sk0 := generateECDSAKey(t)
	signer1, err := jwit.NewSignerFromCryptoKeys([]crypto.PrivateKey{issuer1Sk0})
	if err != nil {
		t.Fatal(err)
	}

	// create a signer that uses a KID
	issuerKIDSk0 := generateECDSAKey(t)
	issuerKIDJWK := jose.JSONWebKey{
		Key:   issuerKIDSk0,
		KeyID: "myKey123",
	}
	issuerKIDJWKS, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{issuerKIDJWK}})
	if err != nil {
		t.Fatal(err)
	}
	signerKID, err := jwit.NewSignerFromJWKS(issuerKIDJWKS)
	if err != nil {
		t.Fatal(err)
	}

	// create an issuer with local keys.
	issuerLocalSk0 := generateECDSAKey(t)
	issuerLocalSk1, err := ioutil.ReadFile(path.Join(".testdata/jwks.json"))
	if err != nil {
		t.Fatal(err)
	}
	issuerLocalSk2, err := ioutil.ReadFile(path.Join(".testdata/private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	signerLocal, err := jwit.NewSignerFromCryptoKeys([]crypto.PrivateKey{issuerLocalSk0})
	if err != nil {
		t.Fatal(err)
	}

	callback := func() {}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		url := req.URL.String()

		switch url {
		case "/.well-known/jwks.json":
			callback()
			jwks, err := signer0.DumpPublicJWKS()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(jwks)
		case "/iss1.json":
			jwks, err := signer1.DumpPublicJWKS()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(jwks)
		case "/kid.json":
			jwks, err := signerKID.DumpPublicJWKS()
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write(jwks)
		case "/302":
			http.Redirect(w, req, "https://malicious.website/jwks.json", http.StatusPermanentRedirect)
		case "/notjson":
			_, err := w.Write([]byte("{not json}"))
			if err != nil {
				t.Fatal(err)
			}
		}
	}))
	defer server.Close()

	verifier, err := jwit.NewVerifier(
		&jwit.Issuer{Name: "iss0", JWKSURL: server.URL + "/.well-known/jwks.json"},
		&jwit.Issuer{Name: "iss1", JWKSURL: server.URL + "/iss1.json"},
		&jwit.Issuer{Name: "issKID", JWKSURL: server.URL + "/kid.json"},
		&jwit.Issuer{Name: "issRedirect", JWKSURL: server.URL + "/302"},
		&jwit.Issuer{Name: "issNotJSON", JWKSURL: server.URL + "/notjson"},
		&jwit.Issuer{Name: "issLowTTL", JWKSURL: server.URL + "/lowttl", TTL: time.Duration(0)},
		&jwit.Issuer{
			Name:       "issLocal",
			PublicKeys: []interface{}{issuerLocalSk0, issuerLocalSk1, issuerLocalSk2},
		},
	)
	if err != nil {
		t.Error("unexpected error", err)
	}

	// Test JWT verification via remote JWKS

	t.Run("test verify a JWT", func(t *testing.T) {
		type CustomClaims struct {
			Payload string `json:"payload"`
		}

		rawJWT, err := signer0.SignJWT(
			jwit.C{Issuer: "iss0"},
			CustomClaims{Payload: "the payload"},
		)
		if err != nil {
			t.Fatal(err)
		}

		var out CustomClaims
		isValid, err := verifier.VerifyJWT(rawJWT, &out)
		if err != nil {
			t.Fatal("unexpected error", err)
		}
		if !isValid {
			t.Fatal("expected token to be valid")
		}
		if out.Payload != "the payload" {
			t.Fatal("unexpected payload", out.Payload)
		}
	})

	t.Run("test verify JWT with bad issuer", func(t *testing.T) {
		rawJWT, err := signer0.SignJWT(
			// Claim we're iss1 although we signed using iss0 SK.
			jwit.C{Issuer: "iss1"},
		)
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err != jwit.ErrUnexpectedSignature {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("test verify JWT with unknown issuer", func(t *testing.T) {
		rawJWT, err := signer0.SignJWT(jwit.C{Issuer: "unknown issuer"})
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err != jwit.ErrUnknownIssuer {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("test verify JWT with redirection", func(t *testing.T) {
		rawJWT, err := signer0.SignJWT(jwit.C{Issuer: "issRedirect"})
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err != jwit.ErrJWKSFetchFailed {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("test verify JWT invalid", func(t *testing.T) {
		isValid, err := verifier.VerifyJWT("this.invalid.jwt")
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if !strings.Contains(err.Error(), "invalid character") {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("test verify JWT expired", func(t *testing.T) {
		rawJWT, err := signer0.SignJWT(
			jwit.C{
				Issuer: "iss0",
				Expiry: time.Now().Add(-1 * time.Hour),
			},
		)
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err != jwt.ErrExpired {
			t.Fatal("unexpected error", err)
		}
	})

	t.Run("test verify JWT with invalid issuer", func(t *testing.T) {
		type CustomClaims struct {
			Issuer map[string]string `json:"iss"`
		}

		rawJWT, err := signer0.SignJWT(
			jwit.C{},
			CustomClaims{Issuer: map[string]string{}},
		)
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err != jwit.ErrUnknownIssuer {
			t.Fatal("expected token to be valid, but got error", err)
		}
	})

	t.Run("test verify JWT deserialization error", func(t *testing.T) {
		type CustomClaims struct {
			Payload string
		}
		type CustomClaimsIncompatible struct {
			Payload int
		}

		rawJWT, err := signer0.SignJWT(
			jwit.C{Issuer: "iss0"},
			CustomClaims{Payload: "abc"},
		)
		if err != nil {
			t.Fatal(err)
		}

		var customClaimsIncompatible CustomClaimsIncompatible
		isValid, err := verifier.VerifyJWT(rawJWT, &customClaimsIncompatible)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if err.Error() != "json: cannot unmarshal string into Go value of type int" {
			t.Fatal("expected token to be valid, but got error", err)
		}
	})

	t.Run("test verify a JWT with KID", func(t *testing.T) {
		rawJWT, err := signerKID.SignJWT(jwit.C{Issuer: "issKID"})
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if err != nil {
			t.Fatal("unexpected error", err)
		}
		if !isValid {
			t.Fatal("expected token to be valid")
		}
	})

	// Test JWT verification via locally stored keys

	t.Run("test local issuer", func(t *testing.T) {
		rawJWT, err := signerLocal.SignJWT(jwit.C{Issuer: "issLocal"})
		if err != nil {
			t.Fatal(err)
		}

		isValid, err := verifier.VerifyJWT(rawJWT)
		if err != nil {
			t.Error("unexpected error", err)
		}
		if !isValid {
			t.Error("expected token to be valid")
		}
	})

	// Test JWT verification via explicit crypto keys

	t.Run("test verify a JWT with crypto keys", func(t *testing.T) {
		type CustomClaims struct {
			Payload string `json:"payload"`
		}

		rawJWT, err := signer1.SignJWT(
			jwit.C{Issuer: "iss1"},
			CustomClaims{Payload: "the payload"},
		)
		if err != nil {
			t.Fatal(err)
		}

		var out CustomClaims
		isValid, err := verifier.VerifyJWTWithKeys(
			rawJWT,
			[]crypto.PublicKey{&issuer1Sk0.PublicKey},
			&out,
		)
		if err != nil {
			t.Fatal("unexpected error", err)
		}
		if !isValid {
			t.Fatal("expected token to be valid")
		}
		if out.Payload != "the payload" {
			t.Fatal("unexpected payload", out.Payload)
		}
	})

	t.Run("test verify a JWT with crypto keys", func(t *testing.T) {
		isValid, err := verifier.VerifyJWTWithKeys(
			"some.invalid.jwt",
			[]crypto.PublicKey{&issuer1Sk0.PublicKey},
		)
		if isValid {
			t.Fatal("expected token to be invalid")
		}
		if !strings.Contains(err.Error(), "invalid character") {
			t.Fatal("unexpected error", err)
		}
	})

	// Test JWKS Refreshing (TTL)

	t.Run("test that keys are fetched once", func(t *testing.T) {
		verifier, err := jwit.NewVerifier(&jwit.Issuer{
			Name:    "iss0",
			JWKSURL: server.URL + "/.well-known/jwks.json",
		})
		if err != nil {
			t.Error("unexpected error", err)
		}

		nbCalls := 0
		callback = func() { nbCalls = nbCalls + 1 }

		rawJWT, err := signer0.SignJWT(jwit.C{Issuer: "iss0"})
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < 10; i++ {
			_, err = verifier.VerifyJWT(rawJWT)
			if err != nil {
				t.Fatal(err)
			}
		}
		if nbCalls != 1 {
			t.Error("unexpected number of calls", nbCalls)
		}
	})

	t.Run("test that keys are fetched again after TTL", func(t *testing.T) {
		verifier, err := jwit.NewVerifier(&jwit.Issuer{
			Name:    "iss0",
			JWKSURL: server.URL + "/.well-known/jwks.json",
			TTL:     1 * time.Nanosecond,
		})
		if err != nil {
			t.Error("unexpected error", err)
		}

		nbCalls := 0
		callback = func() { nbCalls = nbCalls + 1 }

		rawJWT, err := signer0.SignJWT(jwit.C{Issuer: "iss0"})
		if err != nil {
			t.Fatal(err)
		}

		for i := 0; i < 2; i++ {
			_, err = verifier.VerifyJWT(rawJWT)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if nbCalls != 2 {
			t.Error("unexpected number of calls", nbCalls)
		}
	})

	// Test edge cases

	t.Run("test non-json response in JWKS route", func(t *testing.T) {
		rawJWT, err := signer0.SignJWT(jwit.C{Issuer: "issNotJSON"})
		if err != nil {
			t.Fatal(err)
		}

		isVerified, err := verifier.VerifyJWT(rawJWT)
		if isVerified {
			t.Error("expected token to be invalid")
		}
		if !strings.Contains(err.Error(), "invalid character") {
			t.Error("unexpected error", err)
		}
	})

	t.Run("test the none alg joke", func(t *testing.T) {
		// More info: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
		for _, rawJWT := range []string{
			"eyJhbGciOiJub25lIn0",
			"eyJhbGciOiJub25lIn0.",
			"eyJhbGciOiJub25lIn0..",
			"eyJhbGciOiJub25lIn0.e30.",
			"eyJhbGciOiJub25lIiwiaXNzIjoiaXNzMCJ9.e30.",
		} {
			t.Run(rawJWT, func(t *testing.T) {
				isVerified, err := verifier.VerifyJWTWithKeys(rawJWT, []crypto.PublicKey{issuer1Sk0})
				if isVerified {
					t.Error("expected token to be invalid")
				}
				if err == nil {
					t.Error("expected an error ")
				}
			})
		}
	})

	t.Run("test create issuer with invalid data", func(t *testing.T) {
		verifier, err := jwit.NewVerifier(&jwit.Issuer{
			Name:       "issInvalidData",
			PublicKeys: []interface{}{[]byte(`{not json data}`)},
		})
		if !strings.Contains(err.Error(), "invalid character") {
			t.Error("unexpected error", err)
		}
		if verifier != nil {
			t.Error("unexpected verifier", verifier)
		}
	})
}
