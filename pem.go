package jwit

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/go-jose/go-jose/v4"
)

// pemToJWKS converts raw PEM-encoded data to a JWKS.
func pemToJWKS(pemBytes []byte) (jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet
	var block *pem.Block

	for {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}

		key, err := pemBlockToKey(block)
		if err != nil {
			return jwks, err
		}

		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{Key: key})
	}

	return jwks, nil
}

// pemBlockToKey converts a PEM block to a key object.
func pemBlockToKey(block *pem.Block) (interface{}, error) {
	var key interface{}
	var err error

	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	return nil, ErrUnknownKeyType
}
