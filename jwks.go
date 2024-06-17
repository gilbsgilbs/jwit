package jwit

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v4"
)

// loadJWKS loads the provided bytes into a go-jose JSON Web Key Set.
func loadJWKS(jwksBytes []byte) (jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return jwks, err
	}
	return jwks, nil
}

// dumpJWKS dumps the provided go-jose JSON Web Key Set into its bytes representation.
func dumpJWKS(jwks jose.JSONWebKeySet) ([]byte, error) {
	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, err
	}
	return jwksBytes, nil
}
