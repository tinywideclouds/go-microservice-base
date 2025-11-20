package microservice_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-microservice-base/pkg/microservice"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// TestIntegration_FullLifecycle simulates a real service startup,
// authentication against a mock OIDC provider, and graceful shutdown.
func TestIntegration_FullLifecycle(t *testing.T) {
	// 1. Setup Mock Identity Provider (IDP)
	// We need a real RSA key pair to sign tokens and serve public keys.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a JWK from the public key to serve at the mock JWKS endpoint.
	pubKey, err := jwk.FromRaw(privKey.PublicKey)
	require.NoError(t, err)
	_ = pubKey.Set(jwk.KeyIDKey, "test-key-id")
	_ = pubKey.Set(jwk.AlgorithmKey, "RS256")

	// Start the Mock IDP Server
	mockIDP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve the JWK Set
		// FIXED: v2 NewSet() takes no arguments. We must add the key explicitly.
		ks := jwk.NewSet()
		if err := ks.AddKey(pubKey); err != nil {
			http.Error(w, "Failed to add key to set", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(ks); err != nil {
			http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
		}
	}))
	defer mockIDP.Close()

	// 2. Setup the Microservice
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use port :0 to let the OS assign a free port.
	server := microservice.NewBaseServer(logger, ":0")

	// Initialize the Auth Middleware pointing to our Mock IDP.
	// Note: We point directly to the mock server URL which serves the JSON.
	authMiddleware, err := middleware.NewJWKSAuthMiddleware(mockIDP.URL, logger)
	require.NoError(t, err)

	// Register a "Protected" Endpoint
	server.Mux().Handle("/protected", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := middleware.GetUserIDFromContext(r.Context())
		if !ok {
			http.Error(w, "User ID not found in context", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, " + userID))
	})))

	// 3. Start the Service (in a goroutine)
	readyChan := make(chan struct{})
	server.SetReadyChannel(readyChan)

	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			// Panic in the goroutine is bad practice in prod, but fails the test visibly here.
			panic(fmt.Sprintf("Server failed to start: %v", err))
		}
	}()

	// Wait for server to listen
	select {
	case <-readyChan:
		// Server is up
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for server to start")
	}

	// Construct the base URL for the service
	baseURL := "http://127.0.0.1" + server.GetHTTPPort()
	client := &http.Client{Timeout: 1 * time.Second}

	// 4. Test Scenario: Unauthenticated Request
	t.Run("Unauthenticated Request", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/protected")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	// 5. Test Scenario: Authenticated Request (Happy Path)
	t.Run("Authenticated Request", func(t *testing.T) {
		// Generate a valid JWT signed by our Mock IDP's private key
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "user-123",
			"iss": "mock-issuer",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		})
		// Critical: The kid header must match the one in the JWKS
		token.Header["kid"] = "test-key-id"

		signedToken, err := token.SignedString(privKey)
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", baseURL+"/protected", nil)
		req.Header.Set("Authorization", "Bearer "+signedToken)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Hello, user-123", string(body))
	})

	// 6. Test Scenario: Metrics Endpoint (VictoriaMetrics)
	t.Run("Metrics Endpoint", func(t *testing.T) {
		resp, err := client.Get(baseURL + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		// VictoriaMetrics/metrics usually returns at least generic go runtime info.
		// We just want to ensure the endpoint is hooked up and returning text.
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "go_memstats_alloc_bytes")
	})

	// 7. Test Scenario: Graceful Shutdown
	t.Run("Graceful Shutdown", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := server.Shutdown(ctx)
		require.NoError(t, err)
	})
}
