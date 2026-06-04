package adapters

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	nethttp "net/http"
)

type jwksCache struct {
	keys   []jwkKey
	expiry time.Time
}

type jwkKey struct {
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kty string `json:"kty"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwtHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type jwtClaims struct {
	Aud           string `json:"aud"`
	Exp           int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

var (
	jwksStore    sync.Map
	jwksFetchURL = "https://www.googleapis.com/oauth2/v3/certs"
)

func getJWKS() ([]jwkKey, error) {
	val, ok := jwksStore.Load("jwks")
	if ok {
		cache := val.(jwksCache)
		if time.Now().Before(cache.expiry) {
			return cache.keys, nil
		}
	}

	resp, err := nethttp.Get(jwksFetchURL)
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

func findJWK(keys []jwkKey, kid string) *jwkKey {
	for _, k := range keys {
		if k.Kid == kid {
			return &k
		}
	}
	return nil
}

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

func PubSubJWTMiddleware(expectedAud string, next nethttp.Handler) nethttp.Handler {
	return nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 7 || auth[:7] != "Bearer " {
			httpError(w, 401)
			return
		}
		token := auth[7:]

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

func httpError(w nethttp.ResponseWriter, code int) {
	nethttp.Error(w, "Unauthorized", code)
}
