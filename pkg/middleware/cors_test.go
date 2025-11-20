package middleware_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// newTestLogger creates a discard logger for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCorsMiddleware_Roles(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	baseOrigins := []string{"https://safe-domain.com"}
	logger := newTestLogger()

	testCases := []struct {
		name                   string
		config                 middleware.CorsConfig
		expectedAllowedMethods string
	}{
		{
			name: "Default Role",
			config: middleware.CorsConfig{
				AllowedOrigins: baseOrigins,
				Role:           middleware.CorsRoleDefault,
			},
			expectedAllowedMethods: "POST, GET, OPTIONS",
		},
		{
			name: "Editor Role",
			config: middleware.CorsConfig{
				AllowedOrigins: baseOrigins,
				Role:           middleware.CorsRoleEditor,
			},
			expectedAllowedMethods: "POST, GET, OPTIONS, PUT, PATCH",
		},
		{
			name: "Admin Role",
			config: middleware.CorsConfig{
				AllowedOrigins: baseOrigins,
				Role:           middleware.CorsRoleAdmin,
			},
			expectedAllowedMethods: "POST, GET, OPTIONS, PUT, PATCH, DELETE",
		},
		{
			name: "No Role Specified (falls back to default)",
			config: middleware.CorsConfig{
				AllowedOrigins: baseOrigins,
				// Role is omitted
			},
			expectedAllowedMethods: "POST, GET, OPTIONS",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			corsMiddleware := middleware.NewCorsMiddleware(tc.config, logger)
			handlerWithCors := corsMiddleware(testHandler)

			req := httptest.NewRequest(http.MethodOptions, "/", nil)
			req.Header.Set("Origin", "https://safe-domain.com")
			req.Header.Set("Access-Control-Request-Method", "POST") // A typical preflight header
			rr := httptest.NewRecorder()

			// Act
			handlerWithCors.ServeHTTP(rr, req)

			// Assert
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "https://safe-domain.com", rr.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, tc.expectedAllowedMethods, rr.Header().Get("Access-Control-Allow-Methods"))
		})
	}
}

func TestCorsMiddleware_OriginLogic(t *testing.T) {
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	logger := newTestLogger()

	corsCfg := middleware.CorsConfig{
		AllowedOrigins: []string{"http://localhost:3000"},
		Role:           middleware.CorsRoleDefault,
	}
	corsMiddleware := middleware.NewCorsMiddleware(corsCfg, logger)
	handlerWithCors := corsMiddleware(testHandler)

	t.Run("Disallowed Origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "http://disallowed-domain.com")
		rr := httptest.NewRecorder()

		handlerWithCors.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		// CRITICAL: The Allow-Origin header should NOT be set for disallowed origins.
		assert.Empty(t, rr.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestCorsMiddleware_PanicOnWildcard(t *testing.T) {
	logger := newTestLogger()
	corsCfg := middleware.CorsConfig{
		AllowedOrigins: []string{"*"},
		Role:           middleware.CorsRoleDefault,
	}

	assert.Panics(t, func() {
		middleware.NewCorsMiddleware(corsCfg, logger)
	}, "Middleware should panic when configured with insecure wildcard origin")
}
