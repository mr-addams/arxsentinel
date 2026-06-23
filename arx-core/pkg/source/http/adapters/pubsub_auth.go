// ====== Module: GCP Pub/Sub JWT Authentication ======
// Validates OIDC JWT tokens from GCP Pub/Sub push subscriptions.
// Fetches JWKS from Google, validates RS256 signatures, and checks claims.

package adapters

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	nethttp "net/http"
)

// jwksCache caches Google JWKS with TTL to avoid repeated fetches.
type jwksCache struct {
	keys   []jwkKey  // YAML: RSA public keys from Google JWKS endpoint
	expiry time.Time // YAML: cache expiry (1 hour TTL)
}

// jwkKey represents an RSA public key from Google JWKS.
type jwkKey struct {
	Kid string `json:"kid"` // YAML: key ID for matching JWT header
	N   string `json:"n"`   // YAML: base64.RawURLEncoding modulus
	E   string `json:"e"`   // YAML: base64.RawURLEncoding exponent
	Kty string `json:"kty"` // YAML: key type (always "RSA")
}

// jwksResponse wraps JWKS key array.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

// jwtHeader represents JWT header (before payload).
type jwtHeader struct {
	Kid string `json:"kid"` // YAML: key ID to find matching JWK
	Alg string `json:"alg"` // YAML: algorithm (must be RS256)
}

// jwtClaims represents JWT payload claims for Pub/Sub validation.
type jwtClaims struct {
	Aud           string `json:"aud"`            // YAML: audience (must match endpoint URL)
	Exp           int64  `json:"exp"`            // YAML: expiration timestamp (must be in future)
	Email         string `json:"email"`          // YAML: service account email (must be non-empty)
	EmailVerified bool   `json:"email_verified"` // YAML: must be true for valid service accounts
}

// jwksStore is a sync.Map cache for JWKS responses (key: "jwks").
var (
	jwksStore    sync.Map
	jwksFetchURL = "https://www.googleapis.com/oauth2/v3/certs"

	// jwksHTTPClient is a dedicated HTTP client with a 10s timeout for JWKS fetches.
	// Prevents hang on network issues (M4).
	jwksHTTPClient = &nethttp.Client{Timeout: 10 * time.Second}
)

// getJWKS fetches Google JWKS, returns cached version if still valid.
// Returns error if fetch fails or response is malformed.
// Called from: PubSubJWTMiddleware() during JWT validation.
func getJWKS() ([]jwkKey, error) {
	val, ok := jwksStore.Load("jwks")
	if ok {
		cache := val.(jwksCache)
		if time.Now().Before(cache.expiry) {
			return cache.keys, nil
		}
	}

	resp, err := jwksHTTPClient.Get(jwksFetchURL)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("jwks read: %w", err)
	}

	var jr jwksResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		return nil, fmt.Errorf("jwks decode: %w", err)
	}

	keysCopy := make([]jwkKey, len(jr.Keys))
	copy(keysCopy, jr.Keys)
	cache := jwksCache{
		keys:   keysCopy,
		expiry: time.Now().Add(1 * time.Hour),
	}
	jwksStore.Store("jwks", cache)
	return keysCopy, nil
}

// findJWK searches for a key by kid in the JWKS array.
// Returns nil if not found. Non-blocking. Called from: PubSubJWTMiddleware().
func findJWK(keys []jwkKey, kid string) *jwkKey {
	for _, k := range keys {
		if k.Kid == kid {
			return &k
		}
	}
	return nil
}

// jwkToPublicKey converts JWK RSA key to crypto.PublicKey.
// Handles variable-length exponent encoding (1 or 3 bytes).
// Returns error if N or E decode fails. Non-blocking.
func jwkToPublicKey(jk *jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jk.N)
	if err != nil {
		return nil, fmt.Errorf("jwk n decode: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jk.E)
	if err != nil {
		return nil, fmt.Errorf("jwk e decode: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)

	var e int
	if len(eBytes) == 3 {
		e = int(eBytes[0])<<16 | int(eBytes[1])<<8 | int(eBytes[2])
	} else if len(eBytes) == 1 {
		e = int(eBytes[0])
	} else {
		return nil, fmt.Errorf("jwk e: unsupported length %d", len(eBytes))
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// PubSubJWTMiddleware validates OIDC JWT from GCP Pub/Sub push subscriptions.
// If expectedToken is non-empty, compares the Bearer token via ConstantTimeCompare
// to prevent timing attacks. Then validates: RS256 algorithm, signature, audience, email.
// Adds middleware before pubsub handler in buildPushHandler().
// Returns 401 if any validation fails. Non-blocking.
func PubSubJWTMiddleware(expectedAud string, expectedToken string, next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		// Bounds guard before slicing; actual token comparison uses ConstantTimeCompare below.
		if len(auth) < 7 {
			httpError(w, 401)
			return
		}
		if auth[:7] != "Bearer " {
			httpError(w, 401)
			return
		}
		token := auth[7:]

		// Constant-time comparison of the full token prevents timing leaks (M5).
		if expectedToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			httpError(w, 401)
			return
		}

		parts := splitJWT(token)
		if len(parts) != 3 {
			httpError(w, 401)
			return
		}

		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			httpError(w, 401)
			return
		}
		var hdr jwtHeader
		if err := json.Unmarshal(headerJSON, &hdr); err != nil {
			httpError(w, 401)
			return
		}
		if hdr.Alg != "RS256" {
			httpError(w, 401)
			return
		}

		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			httpError(w, 401)
			return
		}
		var claims jwtClaims
		if err := json.Unmarshal(payloadJSON, &claims); err != nil {
			httpError(w, 401)
			return
		}
		if time.Now().Unix() > claims.Exp {
			httpError(w, 401)
			return
		}
		if claims.Aud != expectedAud {
			httpError(w, 401)
			return
		}
		if claims.Email == "" || !claims.EmailVerified {
			httpError(w, 401)
			return
		}

		sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			httpError(w, 401)
			return
		}

		keys, err := getJWKS()
		if err != nil {
			httpError(w, 401)
			return
		}

		jwk := findJWK(keys, hdr.Kid)
		if jwk == nil {
			httpError(w, 401)
			return
		}

		pubKey, err := jwkToPublicKey(jwk)
		if err != nil {
			httpError(w, 401)
			return
		}

		signingInput := parts[0] + "." + parts[1]
		hash := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
			httpError(w, 401)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// splitJWT splits JWT into header.payload.signature parts.
// Manual parse to avoid string splitting on last segment ambiguity.
// Non-blocking. Called from: PubSubJWTMiddleware().
func splitJWT(token string) []string {
	parts := make([]string, 0, 3)
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// httpError writes HTTP error response. Non-blocking.
func httpError(w nethttp.ResponseWriter, code int) {
	nethttp.Error(w, "Unauthorized", code)
}
