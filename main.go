package main

// A simple JWKS server in Go that generates RSA keys, serves JWKS, and issues JWTs.
// It maintains an active key and an expired key for testing purposes.
import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "log"
    "math/big"
    "net/http"
    "strings"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

// KeyRecord holds information about an RSA key pair and its metadata.
type KeyRecord struct {
    KID      string    `json:"kid"`
    Private  *rsa.PrivateKey
    PublicJWK map[string]interface{}
    ExpiresAt time.Time
}

// Store keys in memory.
var keys []KeyRecord

// base64url encodes a byte slice without padding (required for JWK format).
func base64url(b []byte) string {
    s := base64.StdEncoding.EncodeToString(b)
    return strings.TrimRight(s, "=")
}

// generateRSAKey generates a new RSA private key (2048 bits).
func generateRSAKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

// privateKeyToJWK converts an RSA private key to its corresponding JWK representation.
func privateKeyToJWK(priv *rsa.PrivateKey) map[string]interface{} {
    pub := &priv.PublicKey
    
    // Extract modulus (n) and exponent (e) from public key
    n := pub.N
    e := pub.E

    // Convert to base64url encoding (required for JWK standard)
    nBytes := n.Bytes()
    eBytes := big.NewInt(int64(e)).Bytes()

    jwk := map[string]interface{}{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n":   base64url(nBytes),
        "e":   base64url(eBytes),
        // kid will be set after JWK creation by caller
    }
    
    return jwk
}

// initializeKeys creates one active key (expires in 10 minutes) 
// and one expired key (expired 5 minutes ago) for testing.
func initializeKeys() {
    // Generate an active key which will expire in 10 minutes.
    privActive, err := generateRSAKey()
    if err != nil {
        log.Fatal("Failed to generate active key:", err)
    }

    activeKID := uuid.New().String()
    activeJWK := privateKeyToJWK(privActive)
    activeJWK["kid"] = activeKID  // Set kid after JWK creation
    activeExpires := time.Now().Add(10 * time.Minute)
    
    keys = append(keys, KeyRecord{
        KID:      activeKID,
        Private:  privActive,
        PublicJWK: activeJWK,
        ExpiresAt: activeExpires,
    })
    
    fmt.Printf("Generated active key %s (expires %s)\n", activeKID, activeExpires.Format(time.RFC3339))
    
    // Generate an expired key which has already expired 5 minutes ago.
    privExpired, err := generateRSAKey()
    if err != nil {
        log.Fatal("Failed to generate expired key:", err)
    }
    
    expiredKID := uuid.New().String()
    expiredJWK := privateKeyToJWK(privExpired)
    expiredJWK["kid"] = expiredKID  // Set kid after JWK creation
    expiredExpires := time.Now().Add(-5 * time.Minute)
    
    keys = append(keys, KeyRecord{
        KID:      expiredKID,
        Private:  privExpired,
        PublicJWK: expiredJWK,
        ExpiresAt: expiredExpires,
    })
    
    fmt.Printf("Generated expired key %s (expired %s)\n", expiredKID, expiredExpires.Format(time.RFC3339))
}

// jwksHandler serves the JWKS endpoint (GET /jwks).
// Only returns public keys that have not expired.
func jwksHandler(w http.ResponseWriter, r *http.Request) {
    now := time.Now()
    
    var activeKeys []map[string]interface{}
    for _, key := range keys {
        if key.ExpiresAt.After(now) {
            activeKeys = append(activeKeys, key.PublicJWK)
        }
    }
    
    response := map[string]interface{}{
        "keys": activeKeys,
    }
    
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")  // For test client
    json.NewEncoder(w).Encode(response)
}

// authHandler serves the authentication endpoint (POST /auth).
// Issues JWTs signed with active key (normal) or expired key (?expired=true).
func authHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    useExpired := r.URL.Query().Has("expired")
    
    var signingKey *rsa.PrivateKey
    var kid string
    
    now := time.Now()
    
    if useExpired {
        // Find first expired key for testing expired JWTs.
        for _, key := range keys {
            if key.ExpiresAt.Before(now) {
                signingKey = key.Private
                kid = key.KID
                break
            }
        }
    } else {
        // Find first active key for normal JWTs.
        for _, key := range keys {
            if key.ExpiresAt.After(now) {
                signingKey = key.Private
                kid = key.KID
                break
            }
        }
    }
    
    if signingKey == nil {
        http.Error(w, "No suitable key found", http.StatusInternalServerError)
        return
    }
    
    // Create JWT claims.
    claims := jwt.MapClaims{
        "sub":   "fake-user",
        "iat":   now.Unix(),
        "scope": "basic",
    }
    
    if useExpired {
        // Set JWT expiration 2 minutes in the past (expired JWT).
        claims["exp"] = now.Add(-2 * time.Minute).Unix()
    } else {
        // Set JWT expiration 5 minutes in the future (valid JWT).
        claims["exp"] = now.Add(5 * time.Minute).Unix()
    }
    
    // Sign JWT with RS256 and include kid header.
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = kid
    
    signedToken, err := token.SignedString(signingKey)
    if err != nil {
        http.Error(w, "Failed to sign token", http.StatusInternalServerError)
        return
    }
    
    response := map[string]interface{}{
        "access_token": signedToken,
        "token_type":   "Bearer",
        "expires_in":   300,
    }
    
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")  // For test client
    json.NewEncoder(w).Encode(response)
}

func main() {
    // Initialize RSA keys on startup.
    initializeKeys()
    
    // Register HTTP handlers.
    http.HandleFunc("/jwks", jwksHandler)
    http.HandleFunc("/auth", authHandler)
    
    // Start server on port 8080.
    fmt.Println("JWKS Server starting on :8080")
    fmt.Println("Endpoints:")
    fmt.Println("  GET  /jwks           → Active public keys only")
    fmt.Println("  POST /auth           → Valid JWT (active key)")
    fmt.Println("  POST /auth?expired=true → Expired JWT (expired key)")
    fmt.Println("")
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
