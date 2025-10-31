package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestDiscoverAndValidateJWTConfig(t *testing.T) {
	// A valid metadata response for the happy path test case.
	validMetadataResponse := `{
		"issuer": "http://localhost:3000",
		"jwks_uri": "http://localhost:3000/.well-known/jwks.json",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`

	// Define test cases in a table for clarity and easy extension.
	testCases := []struct {
		name              string
		mockServerHandler http.HandlerFunc
		requiredAlg       string
		expectErr         bool
		expectedJWKSURI   string
	}{
		{
			name: "Success - Happy Path",
			mockServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(validMetadataResponse))
			},
			requiredAlg:     "RS256",
			expectErr:       false,
			expectedJWKSURI: "http://localhost:3000/.well-known/jwks.json",
		},
		{
			name: "Failure - Server Returns 500 Error",
			mockServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			requiredAlg: "RS256",
			expectErr:   true,
		},
		{
			name: "Failure - Malformed JSON Response",
			mockServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jwks_uri": "missing-quote`))
			},
			requiredAlg: "RS256",
			expectErr:   true,
		},
		{
			name: "Failure - Required Algorithm Not Supported",
			mockServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// The identity service only supports ES256 in this scenario.
				_, _ = w.Write([]byte(`{
					"jwks_uri": "http://localhost:3000/.well-known/jwks.json",
					"id_token_signing_alg_values_supported": ["ES256"]
				}`))
			},
			requiredAlg: "RS256", // Our service requires RS256.
			expectErr:   true,
		},
		{
			name: "Failure - Algorithm Array is Missing",
			mockServerHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				// The identity service has a malformed metadata response.
				_, _ = w.Write([]byte(`{
					"jwks_uri": "http://localhost:3000/.well-known/jwks.json"
				}`))
			},
			requiredAlg: "RS256",
			expectErr:   true,
		},
	}

	// Create a logger that discards output to keep test logs clean.
	logger := zerolog.New(io.Discard)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new mock HTTP server for each test case.
			server := httptest.NewServer(tc.mockServerHandler)
			defer server.Close()

			// Call the function under test, pointing it at our mock server.
			jwksURI, err := DiscoverAndValidateJWTConfig(server.URL, tc.requiredAlg, logger)

			// Use testify/require for clean and readable assertions.
			if tc.expectErr {
				require.Error(t, err, "Expected an error but got none")
			} else {
				require.NoError(t, err, "Expected no error but got one")
				require.Equal(t, tc.expectedJWKSURI, jwksURI, "The returned JWKS URI was not what was expected")
			}
		})
	}

	// Test case for when the server is down (no mock server running).
	t.Run("Failure - Server is Down", func(t *testing.T) {
		// Pass a non-existent URL.
		_, err := DiscoverAndValidateJWTConfig("http://localhost:9999", "RS256", logger)
		require.Error(t, err, "Expected an error for a down server but got none")
	})
}
