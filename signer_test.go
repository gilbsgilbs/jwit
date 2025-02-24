package jwit_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gilbsgilbs/jwit"
)

func TestSigner(t *testing.T) {
	jwksData, err := ioutil.ReadFile(path.Join(".testdata", "jwks.json"))
	if err != nil {
		t.Fatal(err)
	}

	pksData, err := ioutil.ReadFile(path.Join(".testdata", "pks.json"))
	if err != nil {
		t.Fatal(err)
	}

	publicPEMData, err := ioutil.ReadFile(path.Join(".testdata", "public.pem"))
	if err != nil {
		t.Fatal(err)
	}

	privatePEMData, err := ioutil.ReadFile(path.Join(".testdata", "private.pem"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("test dump JWKS", func(t *testing.T) {
		signer, err := jwit.NewSigner(jwksData, pksData)
		if err != nil {
			t.Error("unexpected error", err)
		}
		var jwks jose.JSONWebKeySet

		// Public JWKS
		jwksBytes, err := signer.DumpPublicJWKS()
		if err != nil {
			t.Error("unexpected error", err)
		}
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			t.Error("unexpected error", err)
		}
		if len(jwks.Keys) != 3 {
			t.Error("unexpected number of public JWK", len(jwks.Keys))
		}
		for _, key := range jwks.Keys {
			isPublic := key.IsPublic()

			if !isPublic {
				t.Error("expected key to be public")
			}
		}

		// Signing JWKS
		jwksBytes, err = signer.DumpSigningJWKS()
		if err != nil {
			t.Error("unexpected error", err)
		}
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			t.Error("unexpected error", err)
		}
		if len(jwks.Keys) != 2 {
			t.Error("unexpected number of signing JWK", len(jwks.Keys))
		}

		// Other JWKS
		jwksBytes, err = signer.DumpOtherJWKS()
		if err != nil {
			t.Error("unexpected error", err)
		}
		if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
			t.Error("unexpected error", err)
		}
		if len(jwks.Keys) != 1 {
			t.Error("unexpected number of other JWK", len(jwks.Keys))
		}
	})

	t.Run("test signer from PEM", func(t *testing.T) {
		signer, err := jwit.NewSigner(privatePEMData, publicPEMData)
		if err != nil {
			t.Error("unexpected error", err)
		}

		verifier, err := jwit.NewVerifier(&jwit.Issuer{
			Name:       "iss",
			PublicKeys: []interface{}{privatePEMData},
		})
		if err != nil {
			t.Fatal(err)
		}

		rawJWT, err := signer.SignJWT(jwit.C{Issuer: "iss"})
		if err != nil {
			t.Error("unexpected error", err)
		}

		isVerified, err := verifier.VerifyJWT(rawJWT)
		if err != nil {
			t.Error("unexpected error", err)
		}
		if !isVerified {
			t.Error("expected token to be verified")
		}
	})

	t.Run("test signer from go crypto keys", func(t *testing.T) {
		pk0, sk0, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Error("unexpected error", err)
		}
		pk1, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Error("unexpected error", err)
		}

		signer, err := jwit.NewSignerFromCryptoKeys(
			[]crypto.PrivateKey{sk0},
			[]crypto.PublicKey{pk1},
		)
		if err != nil {
			t.Error("unexpected error", err)
		}

		verifier, err := jwit.NewVerifier(&jwit.Issuer{
			Name:       "iss",
			PublicKeys: []interface{}{pk0},
		})
		if err != nil {
			t.Fatal(err)
		}

		rawJWT, err := signer.SignJWT(jwit.C{Issuer: "iss"})
		if err != nil {
			t.Error("unexpected error", err)
		}

		isVerified, err := verifier.VerifyJWT(rawJWT)
		if err != nil {
			t.Error("unexpected error", err)
		}
		if !isVerified {
			t.Error("expected token to be verified")
		}
	})

	t.Run("create signer with unknown algorithm", func(t *testing.T) {
		var foo crypto.PrivateKey

		signer, err := jwit.NewSignerFromCryptoKeys([]crypto.PrivateKey{foo})
		if err != jwit.ErrUnknownKeyType {
			t.Error("unexpected error", err)
		}
		if signer != nil {
			t.Error("expected signer to be nil")
		}
	})

	t.Run("create signer with bad JWKS", func(t *testing.T) {
		signer, err := jwit.NewSignerFromJWKS([]byte(`{not json}`))
		if !strings.Contains(err.Error(), "invalid character") {
			t.Error("unexpected error", err)
		}
		if signer != nil {
			t.Error("expecter signer to be nil")
		}

		signer, err = jwit.NewSignerFromJWKS(jwksData, []byte(`{not json}`))
		if !strings.Contains(err.Error(), "invalid character") {
			t.Error("unexpected error", err)
		}
		if signer != nil {
			t.Error("expecter signer to be nil")
		}
	})

	t.Run("create signer with bad PEM", func(t *testing.T) {
		invalidPEMData, err := ioutil.ReadFile(path.Join(".testdata", "invalid.pem"))
		if err != nil {
			t.Fatal(err)
		}

		signer, err := jwit.NewSignerFromPEM(invalidPEMData)
		if err != jwit.ErrUnknownKeyType {
			t.Error("unexpected error", err)
		}
		if signer != nil {
			t.Error("expecter signer to be nil")
		}

		signer, err = jwit.NewSignerFromPEM(privatePEMData, invalidPEMData)
		if err != jwit.ErrUnknownKeyType {
			t.Error("unexpected error", err)
		}
		if signer != nil {
			t.Error("expecter signer to be nil")
		}
	})

	t.Run("sign token with duration", func(t *testing.T) {
		signer, err := jwit.NewSignerFromJWKS(jwksData)
		if err != nil {
			t.Error("unexpected error", err)
		}

		rawJWT, err := signer.SignJWT(jwit.C{Duration: 1 * time.Hour})
		if err != nil {
			t.Error("unexpected error", err)
		}

		parts := strings.Split(rawJWT, ".")
		payload, err := base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			t.Error("unexpected error", err)
		}

		var result map[string]interface{}
		err = json.Unmarshal(payload, &result)
		if err != nil {
			t.Error("unexpected error", err)
		}

		if len(result) != 1 {
			t.Error("unexpected JWT payload", result)
		}
		exp := result["exp"].(float64)
		diff := int64(exp) - time.Now().Unix()
		if !(3599 <= diff && diff <= 3601) {
			t.Error("unexpected diff", diff)
		}
	})
}
