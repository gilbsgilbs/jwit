package jwit

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Issuer is a third-party that publishes a set of public keys.
type Issuer struct {
	sync.Mutex

	// Name is the name of the issuer (corresponding to a "iss" claim)
	Name string

	// PublicKeys is a set of known public keys for this issuer.
	PublicKeys []interface{}

	// JWKSURL is an URL where the issuer publishes its JWKS.
	JWKSURL string

	// TTL defines how long a JWKS are considered "fresh". Past that TTL, jwit will try
	// to refresh the JWKS asynchronously.
	TTL time.Duration

	// localJWKS is a JWKS derived from PublicKeys the user gave when creating the issuer.
	localJWKS jose.JSONWebKeySet

	// jwks is the last JSON Web Key Set known for this issuer. It contains the union of the local
	// JWKS and the JWKS resulting from the last call to JWKSURL.
	jwks jose.JSONWebKeySet

	// lastRefreshedAt shows when the issuer's JWKS were last fetched.
	lastRefreshedAt time.Time
}

// initialize initializes the issuer's default parameters and local JWKS.
func (issuer *Issuer) initialize() error {
	// Set a default expiration to 24 hours.
	if issuer.TTL == time.Duration(0) {
		issuer.TTL = 24 * time.Hour
	}

	// Extract JWKS from provided public keys
	issuer.localJWKS.Keys = make([]jose.JSONWebKey, 0, len(issuer.PublicKeys))
	localKeys := &issuer.localJWKS.Keys
	for _, publicKey := range issuer.PublicKeys {
		switch publicKey := publicKey.(type) {
		case []byte:
			var err error
			var jwks jose.JSONWebKeySet
			firstChar := publicKey[0]
			if firstChar == '{' {
				// Bytes look like a JSON payload. Likely a JWKS.
				jwks, err = loadJWKS(publicKey)
			} else {
				// If it's not a JWKS, then it's probably a PEM.
				jwks, err = pemToJWKS(publicKey)
			}
			if err != nil {
				return err
			}

			for _, key := range jwks.Keys {
				*localKeys = append(*localKeys, key.Public())
			}
		default:
			key := (&jose.JSONWebKey{Key: publicKey}).Public()
			*localKeys = append(*localKeys, key)
		}
	}
	issuer.PublicKeys = nil
	issuer.jwks = issuer.localJWKS

	return nil
}

// needsRefresh checks if the issuer's JWKS have reached TTL.
func (issuer *Issuer) needsRefresh() bool {
	if issuer.JWKSURL == "" {
		return false
	}

	return issuer.TTL <= time.Since(issuer.lastRefreshedAt)
}

// getJWKS returns the issuer's JWKS. Fetches the JWKS if they are missing and schedules a refresh
// of the JWKS if they are out-of-date.
func (issuer *Issuer) getJWKS(client *http.Client) (*jose.JSONWebKeySet, error) {
	jwks := issuer.jwks
	needsRefresh := issuer.needsRefresh()

	if needsRefresh && issuer.lastRefreshedAt.IsZero() {
		// First time we fetch the JWKS, we need to do it synchronously.
		return issuer.refreshJWKS(client)
	}

	if needsRefresh {
		// The JWKS are out of date. Schedule their refresh.
		go func() {
			if _, err := issuer.refreshJWKS(client); err != nil {
				log.Printf("jwit: couldn't fetch issuer's JWKS: %s", err)
			}
		}()
	}

	return &jwks, nil
}

// refreshJWKS thread-safely fetches the issuer's JWKS.
func (issuer *Issuer) refreshJWKS(client *http.Client) (*jose.JSONWebKeySet, error) {
	var jwks jose.JSONWebKeySet

	// Lock the issuer to prevent races
	issuer.Lock()
	defer issuer.Unlock()

	// Check data isn't fresh already (in case it was already fetched by a concurrent goroutine)
	if !issuer.needsRefresh() {
		return &issuer.jwks, nil
	}

	// Make the HTTP request
	resp, err := client.Get(issuer.JWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if !(200 <= resp.StatusCode && resp.StatusCode < 300) {
		return nil, ErrJWKSFetchFailed
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	// Set the JWKS value and return it
	issuer.jwks.Keys = append(issuer.localJWKS.Keys, jwks.Keys...)
	issuer.lastRefreshedAt = time.Now()

	return &jwks, nil
}
