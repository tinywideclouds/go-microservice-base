package middleware

import (
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
	// Example: []string{"http://localhost:4200", "https://my-frontend.com"}
	AllowedOrigins []string
	// Role determines the set of allowed HTTP methods. Defaults to CorsRoleDefault.
	Role CorsRole
}

// NewCorsMiddleware creates a new CORS middleware with the specified configuration.
func NewCorsMiddleware(cfg CorsConfig) func(http.Handler) http.Handler {
	// Create a map for fast origin lookups.
	allowedOrigins := make(map[string]bool)
	for _, origin := range cfg.AllowedOrigins {
		allowedOrigins[origin] = true
	}

	// Determine the allowed methods string based on the configured role.
	var allowedMethods string
	switch cfg.Role {
	case CorsRoleEditor:
		allowedMethods = "POST, GET, OPTIONS, PUT, PATCH"
	case CorsRoleAdmin:
		allowedMethods = "POST, GET, OPTIONS, PUT, PATCH, DELETE"
	default: // Includes CorsRoleDefault
		allowedMethods = "POST, GET, OPTIONS"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Only set the Allow-Origin header if the request origin is in our allowed list.
			if allowedOrigins[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// Handle preflight (OPTIONS) requests.
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
