package main

// Imports the necessary packages.
import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// RSAKey stores a key pair.(kid and expiry)
type RSAKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Expiry     time.Time
	Kid        string
}

// Global in-memory key store.
var keyStore = map[string]RSAKey{}

// Initialize keys (1 valid and 1 expired)
func initKeys() {
	validKey := generateKey(1)   // expires within an hour
	expiredKey := generateKey(-1) // already expired
	keyStore[validKey.Kid] = validKey
	keyStore[expiredKey.Kid] = expiredKey
}

// Generate an RSA key with expiryHours offset.
func generateKey(expiryHours int) RSAKey {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := uuid.New().String()
	return RSAKey{
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		Expiry:     time.Now().Add(time.Duration(expiryHours) * time.Hour),
		Kid:        kid,
	}
}

// JWKS handler. (only returns unexpired keys)
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	keys := []map[string]string{}

	for _, key := range keyStore {
		if key.Expiry.After(time.Now()) {
			n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
			keys = append(keys, map[string]string{
				"kty": "RSA",
				"kid": key.Kid,
				"use": "sig",
				"n":   n,
				"e":   e,
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys})
}

// Auth handler. (returns JWT, optionally with expired key)
func authHandler(w http.ResponseWriter, r *http.Request) {
	expired := r.URL.Query().Get("expired") == "true"
	var chosenKey RSAKey
	found := false

	for _, key := range keyStore {
		if expired && key.Expiry.Before(time.Now()) {
			chosenKey = key
			found = true
			break
		}
		if !expired && key.Expiry.After(time.Now()) {
			chosenKey = key
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "No suitable key found", http.StatusInternalServerError)
		return
	}

	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = chosenKey.Kid
	token.Claims = jwt.MapClaims{
		"sub": "fakeuser",
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	tokenString, err := token.SignedString(chosenKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(tokenString))
}

// Entry point of the application.
func main() {
	initKeys()

	http.HandleFunc("/jwks", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("JWKS server running on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Server failed:", err)
	}
}
