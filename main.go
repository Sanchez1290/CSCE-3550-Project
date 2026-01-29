package main

// This is a simple HTTP server that serves JWKS and handles authentication requests.
import (
    "fmt"
    "net/http"
)

func main() {
    // Initialize keys for JWKS.
    initKeys()

    // Register endpoints for JWKS and authentication.
    http.HandleFunc("/jwks", jwksHandler)
    http.HandleFunc("/auth", authHandler)

    // Then start the HTTP server.
    fmt.Println("Server running on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Println("Failed to start server:", err)
    }
}
