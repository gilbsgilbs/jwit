[![License Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Godoc](https://godoc.org/github.com/gilbsgilbs/jwit?status.svg)](https://pkg.go.dev/github.com/gilbsgilbs/jwit)
[![Actions Status](https://github.com/gilbsgilbs/jwit/workflows/Test/badge.svg)](https://github.com/gilbsgilbs/jwit/actions)
[![Coverage Status](https://coveralls.io/repos/github/gilbsgilbs/jwit/badge.svg?branch=master)](https://coveralls.io/github/gilbsgilbs/jwit?branch=master)

# JWIT

JWIT is a tiny Go library built around [go-jose](https://github.com/square/go-jose) that brings
[JSON Web Tokens (JWTs)](https://auth0.com/learn/json-web-tokens/) and [JSON Web Key Sets (JWKS)](
https://auth0.com/docs/tokens/json-web-tokens/json-web-key-sets) into your apps.

JWIT features:

- A high-level API to sign and verify your asymmetric JWTs.
- A high-level API to publish your public JWKS.

> 💡 As JWIT sticks to the standards and is not tight to any framework, you can actually pick which
> features you want to use. You can use it to just sign JWTs, just verify JWTs you get from a
> third-party and your own servers, or just expose your public JWKS.

One neat use-case:

1. Your authorization server uses JWIT to sign new JWTs.
1. Your authorization server uses JWIT to expose its public keys as a JWKS (usually at
   `/.well-known/jwks.json`).
1. Your resource server uses JWIT to unmarshal incoming JWTs and validate them against your
   authorization server's JWKS.

> 🤯 JWIT will automatically catch changes to the JWKS. Rotating your secrets has never been so
> easy.

## Installation

> go get github.com/gilbsgilbs/jwit

## Overview

This section shows a few basic examples that'll give you a sneak peak of how simple it is to work
with JWIT. For more in-depth examples (such as working with private claims, loading keys from PEM,
…), please head to [the godoc page](https://pkg.go.dev/github.com/gilbsgilbs/jwit).

### Create a signed JWT

```go
// 1. Create a signer from a JSON Web Key Set (JWKS). The JWKS payload will typically reside your
//    authorization server's config or in a secure vault.
signer, err := jwit.NewSigner([]byte(`{"keys": [ ... ]}`))

// 2. Create a JWT that expires in one hour.
rawJWT, err := signer.SignJWT(jwit.C{Duration: 1 * time.Hour})

// 3. That's it, simple as that. rawJWT is a signed JWT token that is ready to serve.
fmt.Println(rawJWT)
```

### Verify a JWT

```go
// 1. Create a verifier
verifier, err := jwit.NewVerifier(
    // Specify an URL to the issuer's public JWKS.
    &jwit.Issuer{
        // This should correspond to the "iss" claims of the JWTs
        Name: "myVeryOwnIssuer",

        // This is an HTTP(S) URL where the authorization server publishes its public keys.
        // It will be queried the first time a JWT is verified and then periodically.
        // If this URL is let empty, remote JWKS are disabled.
        JWKSURL: "https://my-very-own-issuer.com/.well-known/jwks.json",

        // You can specify how long the issuer's public keys should be kept in cache.
        // Passed that delay, the JWKS will be re-fetched once asynchronously.
        // Defaults to 24 hours.
        TTL: 10 * time.Hour,

        // Alternatively, you can specify a set of public keys directly:
        PublicKeys: []interface{}{
            rsaPublicKey, ecdsaPublicKey,
            []byte(`--- BEGIN RSA PUBLIC KEY --- ...`),
            []byte(`{"keys":[ ... JWKS ... ]}`),
        },
    },
    // ... you can specify as many issuers as you want
)

// 2. Verify the JWT using its "iss" claim.
isValid, err := verifier.VerifyJWT(rawJWT)

// Alternatively, if your JWT doesn't have an "iss" claim, you can also pass public keys explicitely.
isValid, err := verifier.VerifyJWTWithKeys(rawJWT, []crypto.PublicKey{ecdsaPublicKey, rsaPublicKey})
```

### Expose the public JWKS

```go
http.HandleFunc(
    "/.well-known/jwks.json",
    func (w http.ResponseWriter, req *http.Request) {
        // Just get the public JWKS from the signer.
        jwks, err := signer.DumpPublicJWKS()

        // And write it to the response body.
        w.Write(jwks)
    },
)
```

## 🔒 Security

If you found a security vulnerability in JWIT itslef, **do not reveal it publicly** and adopt a
[responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure). You may open a
GitHub issue stating that you found a vulnerability and specifying a safe way to get in touch with
you.

Note that JWIT is **not** another JWT/JWKS implementation by any mean. JWIT relies on
[go-jose](https://github.com/square/go-jose), a popular JWx implementation by Square. On top of
that, go-jose and Go's stdlib are the only dependencies to this library. This greatly reduces the
attack surface of JWIT. If you found a security vulnerability in go-jose , plese refer to
[their bug bounty program](https://github.com/square/go-jose/blob/master/BUG-BOUNTY.md).
