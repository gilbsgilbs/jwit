package jwit_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"time"

	"github.com/gilbsgilbs/jwit"
)

// This is a simple example of how to sign a JWT from a JWKS containing private keys.
func Example_signJWT() {
	// Create a signer from a JSON Web Key Set (JWKS) containing private keys.
	// The JWKS payload will typically reside your authorization server's config or in a secure vault.
	signer, _ := jwit.NewSigner([]byte(`{"keys": [ ... private JSON Web Keys ... ]}`))

	// You can optionnaly assign default claims to this signer.
	signer.DefaultClaims.Issuer = "My Authorization Server"
	signer.DefaultClaims.Duration = 1 * time.Hour // Shorthand for "Expiry: time.Now().Add(1 * time.Hour)"

	// Create a JWT that expires in one hour
	rawJWT, _ := signer.SignJWT(jwit.C{
		// You can optionnaly override default claims here
		// Duration: 1 * time.Hour,
	})

	// And that's all!
	fmt.Println("JWT:", rawJWT)
}

// This example shows how to sign a JWT with private claims .
func Example_signJWTWithPrivateClaims() {
	type MyCustomClaims struct {
		Payload string `json:"payload"`
		IsAdmin bool   `json:"is_admin"`
	}

	signer, _ := jwit.NewSigner([]byte(`{"keys": [ ... ]}`))
	signer.DefaultClaims.Duration = 1 * time.Hour

	// Create a JWT with two custom claims
	rawJWT, _ := signer.SignJWT(
		jwit.C{},
		MyCustomClaims{
			Payload: "custom data",
			IsAdmin: false,
		},
	)

	// Done!
	fmt.Println("JWT:", rawJWT)
}

func Example_verifyJWT() {
	var rsaPublicKey *rsa.PublicKey
	var ecdsaPublicKey *ecdsa.PublicKey

	// Create a verifier
	verifier, _ := jwit.NewVerifier(
		// Recommended: specify an URL to the issuer's public JWKS.
		//              this will allow JWIT to catch changes to the JWKS.
		&jwit.Issuer{
			// This should correspond to the "iss" claims of the JWTs
			Name: "myVeryOwnIssuer",

			// This is an HTTP(S) URL where the authorization server publishes its public keys.
			// It will be queried the first time a JWT is verified and then periodically.
			JWKSURL: "https://my-very-own-issuer.com/.well-known/jwks.json",

			// You can specify how long the issuer's public keys should be kept in cache.
			// Passed that delay, the JWKS will be re-fetched once asynchronously.
			// Defaults to 24 hours.
			TTL: 10 * time.Hour,
		},
		// Alternatively: pass in public keys directly.
		&jwit.Issuer{
			Name: "myOtherIssuer",
			PublicKeys: []interface{}{
				// using Go's crypto types
				rsaPublicKey,
				ecdsaPublicKey,
				// or using a marshalled JWKS JSON
				[]byte(`{"keys": [ … your JWKS … ]}`),
				// or using marshalled PEM blocks
				[]byte(`-----BEGIN RSA PUBLIC KEY----- ... -----END RSA PUBLIC KEY-----`),
			},
		},
		// ... you can specify as many issuer as you want
	)

	// You typically get this from a Cookie or Authorization header.
	rawJWT := "ey[...]pX.ey[...]DI.Sf[...]5c"

	// Verify the JWT using its "iss" claim
	isValid, _ := verifier.VerifyJWT(rawJWT)

	if isValid {
		// do stuff
	}
}

// This example shows how to unmarshal private claims from a JWT.
func Example_verifyJWTUnmarshalPrivateClaims() {
	type MyCustomClaims struct {
		Payload string `json:"payload"`
		IsAdmin bool   `json:"is_admin"`
	}

	verifier, _ := jwit.NewVerifier()
	rawJWT := "ey[...]pX.ey[...]DI.Sf[...]5c"

	var myCustomClaims MyCustomClaims
	// if the JWT is valid, the claims will be unmarshaled into myCustomClaims
	isValid, _ := verifier.VerifyJWT(rawJWT, &myCustomClaims)

	if isValid {
		// do stuff
	}
}

// Verifying a JWT against a specific set of keys can sometimes be useful (for example if the JWT
// issuer doesn't provide an "iss" claim or if you don't know the issuer's public key in advance).
// This example demonstrates how you can validate a JWT using your own set of public keys on an
// existing verifier.
func Example_verifyJWTWithGoCryptoKeys() {
	var someECDSAPublicKey *ecdsa.PublicKey
	var someRSAPublicKey *rsa.PublicKey

	// Create a new empty verifyer
	verifier, _ := jwit.NewVerifier()

	// You'll typically get this from a Cookie or Authorization header.
	rawJWT := "ey[...]pX.ey[...]DI.Sf[...]5c"

	// If any of the RSA or ECDSA key was used to sign the JWT, isValid will be set to true.
	isValid, _ := verifier.VerifyJWTWithKeys(
		rawJWT,
		[]crypto.PublicKey{someECDSAPublicKey, someRSAPublicKey},
	)

	if isValid {
		// do stuff
	}
}

// This example shows how you can expose your public JWKS to the world.
func Example_exposeJWKS() {
	// All JWKS listed in NewSigner() will be merged into one JWKS when calling "DumpPublicJWKS()".
	signer, _ := jwit.NewSigner(
		// The first argument must contain your (private) signing keys. If it contains more than one
		// signing keys, one will be picked at random each time you call `signJWT()`.
		[]byte(`{"keys": [ ... some private JSON Web Keys ... ]}`),

		// Following (variadic) arguments are optional and can be private or public keys.
		//
		// They won't be used to sign your JWTs, but will show as public keys in "DumpPublicJWKS()".
		// This is useful when you want to renew your signing keys as you need to make sure resource servers
		// still consider previously created tokens as valid (until they expire). Consequently, you'll usually
		// want to set these to your "old" signing keys, and eventually remove them.
		//
		// Refer to the example dedicated to signing keys renewal for details.
		[]byte(`{"keys": [ ... some JSON Web Keys ... ]}`),
		[]byte(`{"keys": [ ... other JSON Web Keys ... ]}`),
		[]byte(`{"keys": [ ... and so on ... ]}`),
	)

	privateJWKS, _ := signer.DumpSigningJWKS()
	fmt.Println("my private signing JWKS (to keep secret): ", string(privateJWKS))

	otherJWKS, _ := signer.DumpOtherJWKS()
	fmt.Println("my other JWKS (to keep secret):", string(otherJWKS))

	http.HandleFunc(
		"/.well-known/jwks.json",
		func(w http.ResponseWriter, req *http.Request) {
			// This function exposes all the keys as public keys.
			jwks, err := signer.DumpPublicJWKS()
			if err != nil {
				panic(err)
			}
			_, _ = w.Write(jwks)
		},
	)

	_ = http.ListenAndServe(":8080", nil)
}

// This shows how you can create a new signer using a PEM file as signing keys. Note however
// that it is recommended you used JWKS instead.
func Example_signerFromPEM() {
	// Read a standard PEM file that may contain multiple private keys.
	// If the file contains multiple keys, one will be picked at random each time you sign a token.
	pemBytes, _ := ioutil.ReadFile(path.Join("myPrivateKeys.pem"))

	// Signer will detect PEM data vs JWKS data, so you can just do:
	signer, err := jwit.NewSigner(pemBytes)
	// Or if you prefer being explicit:
	// signer, err := jwit.NewSignerFromPEM(pemBytes)
	if err != nil {
		panic(err)
	}

	// you can then use your signer normally
	rawJWT, _ := signer.SignJWT(jwit.C{})

	// and serve this token.
	fmt.Println(rawJWT)
}

// This example shows how to create a new signer using private keys from go's crypto package.
func Example_signerFromGoCrypto() {
	var ecdsaPrivateKey *ecdsa.PrivateKey
	var rsaPrivateKey *rsa.PrivateKey

	// Just create the signer
	signer, err := jwit.NewSignerFromCryptoKeys(
		[]crypto.PrivateKey{
			ecdsaPrivateKey,
			rsaPrivateKey,
			// ... and so on
		},
	)
	if err != nil {
		panic(err)
	}

	// you can then use your signer normally
	rawJWT, _ := signer.SignJWT(jwit.C{})

	// and serve this token.
	fmt.Println(rawJWT)
}

// This example explains step-by-step how to gracefully renew signing keys.
func Example_signerGracefullyRenewSigningKeys() {
	// Let's say your authorization server uses this signer:
	signer, _ := jwit.NewSigner(
		[]byte(`{"keys": [ ... old signing keys ... ]}`),
	)

	// Your authorization server exposes the public keys corresponding to this signer
	// at "/.well-known/jwks.json". Your resource servers use this public JWKS (tied to your
	// old signing keys) to verify the JWTs:
	publicJwks, _ := signer.DumpPublicJWKS()
	fmt.Println("/.well-known/jwks.json => ", string(publicJwks))

	// Now, you can safely replace your signer with this one:
	signer, _ = jwit.NewSigner(
		[]byte(`{"keys": [ ... old signing keys ... ]}`),
		[]byte(`{"keys": [ ... new signing keys ... ]}`),
	)

	// this signer will still sign the JWTs with the same keys as before, but declare the new
	// public signing keys at /.well-known/jwks.json.

	// So this should list the old signing keys along with the new ones.
	publicJwks, _ = signer.DumpPublicJWKS()
	fmt.Println("/.well-known/jwks.json => ", string(publicJwks))

	// You then need to wait for the new public keys to propagate across all your resource servers.
	// How long you need to wait depends on the TTL each resource server has defined.

	// ...

	// Once all resource servers have refreshed the JWKS, you can sign the JWTs with your new keys:
	signer, _ = jwit.NewSigner(
		[]byte(`{"keys": [ ... new signing keys ... ]}`),
		[]byte(`{"keys": [ ... old signing keys ... ]}`),
	)

	// This new signer will sign the JWTs with the new signing keys, but keep the old keys declared
	// in the public JWKS.

	// So this should list should not have changed compared to the previous time:
	publicJwks, _ = signer.DumpPublicJWKS()
	fmt.Println("/.well-known/jwks.json => ", string(publicJwks))

	// Now you need to wait again for all your tokens signed with the old signing keys to expire.
	// How long you need to wait depends on the value of the "exp" claim for each token.

	// ...

	// Finally, you can revoke the old signing keys:
	signer, _ = jwit.NewSigner(
		[]byte(`{"keys": [ ... new signing keys ... ]}`),
	)

	// And this will only list the new public signing keys:
	publicJwks, _ = signer.DumpPublicJWKS()
	fmt.Println("/.well-known/jwks.json => ", string(publicJwks))

	// 👏👏👏👏👏👏👏👏👏👏👏👏👏
}
