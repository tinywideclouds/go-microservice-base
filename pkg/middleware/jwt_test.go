package middleware_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// --- Test Setup for RS256 / JWKS ---

const testKeyID = "test-key-id-1"

// createTestRS256Token generates a JWT signed with the given RSA private key.
func createTestRS256Token(userID, keyID string, privateKey *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	token.Header["kid"] = keyID
	return token.SignedString(privateKey)
}

// newMockJWKSServer creates an httptest.Server that serves a JWKS with the given public key.
func newMockJWKSServer(t *testing.T, keyID string, publicKey *rsa.PublicKey) *httptest.Server {
	t.Helper()

	jwkKey, err := jwk.FromRaw(publicKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, keyID))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, "RS256"))

	keySet := jwk.NewSet()
	require.NoError(t, keySet.AddKey(jwkKey))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(keySet)
		require.NoError(t, err)
	}))
}

func TestNewJWKSManager(t *testing.T) {
	t.Run("Success - Valid URL", func(t *testing.T) {
		// Arrange: Create a key pair and a mock server to serve the public key.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		mockServer := newMockJWKSServer(t, testKeyID, &privateKey.PublicKey)
		defer mockServer.Close()

		// Act: Create the manager, pointing it to our mock server.
		manager, err := middleware.NewJWKSManager(mockServer.URL)

		// Assert: Check that the manager was created successfully and contains our key.
		require.NoError(t, err)
		require.NotNil(t, manager)

		// Verify we can actually look up the key to be sure it was fetched.
		key, found := manager.LookupKeyID(testKeyID)
		assert.True(t, found)
		assert.NotNil(t, key)
	})

	t.Run("Failure - Invalid URL", func(t *testing.T) {
		// Arrange: Create a deliberately non-existent URL.
		invalidURL := "http://127.0.0.1:9999/invalid-path"

		// Act: Attempt to create the manager.
		manager, err := middleware.NewJWKSManager(invalidURL)

		// Assert: Check that an error was returned and the manager is nil.
		require.Error(t, err)
		assert.Nil(t, manager)
		assert.Contains(t, err.Error(), "failed to perform initial JWKS fetch")
	})
}

func TestJWKSAuthMiddleware(t *testing.T) {
	// 1. Generate a real RSA key pair for this test run.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// 2. Start a mock server to act as our JWKS endpoint.
	mockServer := newMockJWKSServer(t, testKeyID, &privateKey.PublicKey)
	defer mockServer.Close()

	// 3. Create the middleware, pointing it to our mock server.
	jwtMiddleware, err := middleware.NewJWKSAuthMiddleware(mockServer.URL)
	require.NoError(t, err, "Middleware should be created successfully")

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := middleware.GetUserIDFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "user-123", userID)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	})
	protectedHandler := jwtMiddleware(testHandler)

	t.Run("Success - Valid RS256 Token", func(t *testing.T) {
		token, err := createTestRS256Token("user-123", testKeyID, privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Failure - Token signed with wrong key", func(t *testing.T) {
		anotherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		token, err := createTestRS256Token("user-123", testKeyID, anotherPrivateKey)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	// Other failure cases like "No Auth Header" and "Invalid Format" are implicitly
	// tested by the legacy middleware test below and behave identically.
}

// --- Test for Legacy HS256 Middleware ---

const testLegacySecret = "my-test-secret"

// createTestHS256Token generates a JWT for testing the legacy middleware.
func createTestHS256Token(userID, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	return token.SignedString([]byte(secret))
}

func TestLegacySharedSecretAuthMiddleware(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, ok := middleware.GetUserIDFromContext(r.Context())
		require.True(t, ok, "userID should be in the context")
		require.Equal(t, "user-123", userID)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	})

	jwtMiddleware := middleware.NewLegacySharedSecretAuthMiddleware(testLegacySecret)
	protectedHandler := jwtMiddleware(testHandler)

	t.Run("Success - Valid HS256 Token", func(t *testing.T) {
		token, err := createTestHS256Token("user-123", testLegacySecret)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()

		protectedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Failure - No Auth Header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		protectedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Failure - Invalid Signature", func(t *testing.T) {
		token, err := createTestHS256Token("user-123", "a-different-secret")
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := httptest.NewRecorder()
		protectedHandler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	userID := "test-user"

	ctxWithUser := middleware.ContextWithUserID(ctx, userID)
	retrievedID, ok := middleware.GetUserIDFromContext(ctxWithUser)

	assert.True(t, ok)
	assert.Equal(t, userID, retrievedID)
}
