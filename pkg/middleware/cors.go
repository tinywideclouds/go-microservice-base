package middleware

import (
	"log/slog"
	"net/http"
)

// CorsRole defines the level of access for allowed HTTP methods.
type CorsRole string

const (
	// CorsRoleDefault allows basic read-only and preflight requests.
	CorsRoleDefault CorsRole = "default"
	// CorsRoleEditor allows methods for creating and updating resources.
	CorsRoleEditor CorsRole = "editor"
	// CorsRoleAdmin allows all standard methods, including deletion.
	CorsRoleAdmin CorsRole = "admin"
)

// CorsConfig holds the configuration for the CORS middleware.
type CorsConfig struct {
	// AllowedOrigins is a list of domains that are allowed to make cross-origin requests.
	// Note: This library forces Access-Control-Allow-Credentials=true.
	// Therefore, usage of the wildcard "*" origin is insecure and prohibited.
	AllowedOrigins []string
	// Role determines the set of allowed HTTP methods. Defaults to CorsRoleDefault.
	Role CorsRole
}

// NewCorsMiddleware creates a new CORS middleware with the specified configuration.
// It will panic if the configuration is insecure (e.g., using wildcard origins with credentials).
func NewCorsMiddleware(cfg CorsConfig, logger *slog.Logger) func(http.Handler) http.Handler {
	allowedOrigins := make(map[string]bool)
	for _, origin := range cfg.AllowedOrigins {
		if origin == "*" {
			// Since this middleware forces Allow-Credentials=true, a wildcard origin
			// is strictly prohibited by browser standards and represents a security flaw.
			panic("microservice/cors: insecure configuration detected. Cannot use wildcard '*' origin with credentials enabled.")
		}
		allowedOrigins[origin] = true
	}

	var allowedMethods string
	switch cfg.Role {
	case CorsRoleEditor:
		allowedMethods = "POST, GET, OPTIONS, PUT, PATCH"
	case CorsRoleAdmin:
		allowedMethods = "POST, GET, OPTIONS, PUT, PATCH, DELETE"
	default:
		allowedMethods = "POST, GET, OPTIONS"
	}

	logger.Debug("CORS middleware configured", "allowed_methods", allowedMethods, "allowed_origins", cfg.AllowedOrigins)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			logger.Debug("CORS: Checking request", "origin", origin, "method", r.Method)

			if allowedOrigins[origin] {
				logger.Debug("CORS: Origin allowed", "origin", origin)
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if origin != "" {
				logger.Debug("CORS: Origin denied", "origin", origin)
			}

			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == "OPTIONS" {
				logger.Debug("CORS: Handling preflight request")
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
