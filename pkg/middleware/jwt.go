package middleware

import (
	"context"
	"fmt"
	"log/slog" // IMPORTED
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"
)

// contextKey is a private type to prevent collisions with other context keys.
type contextKey string

// userContextKey is the key used to store the authenticated user's ID from the JWT.
const userContextKey contextKey = "userID"

type JWTSigningMethod string

const RSA256 JWTSigningMethod = "RS256"

// JWKSManager defines the interface for a key set manager that can be used
// for manual token validation in non-HTTP contexts (e.g., WebSockets).
type JWKSManager jwk.Set

// NewJWKSManager creates a new, auto-refreshing JWKS key set from a remote URL.
// This is the building block for manual token validation.
func NewJWKSManager(jwksURL string) (JWKSManager, error) {
	cache := jwk.NewCache(context.Background())
	err := cache.Register(jwksURL, jwk.WithRefreshInterval(15*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Trigger an initial fetch to ensure the URL is valid and keys are available on startup.
	_, err = cache.Refresh(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to perform initial JWKS fetch: %w", err)
	}

	return jwk.NewCachedSet(cache, jwksURL), nil
}

// NoopAuth is a test helper that bypasses all auth checks
// and simply injects a static user ID into the request context.
func NoopAuth(enabled bool, staticUserID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				response.WriteJSONError(w, http.StatusUnauthorized, "Auth is disabled by test")
				return
			}
			// Use the existing helper to add the user ID to the context
			ctx := ContextWithUserID(r.Context(), staticUserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewJWKSAuthMiddleware is the modern, secure constructor for creating JWT authentication middleware.
// It validates asymmetric RS256 tokens by fetching public keys from a JWKS endpoint.
// This should be the default choice for all new services.
func NewJWKSAuthMiddleware(jwksURL string, logger *slog.Logger) (func(http.Handler) http.Handler, error) { // CHANGED
	// Create a new JWK cache that will automatically fetch and refresh the keys.
	// This is done once on startup for efficiency.
	cache := jwk.NewCache(context.Background())
	err := cache.Register(jwksURL, jwk.WithRefreshInterval(15*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Pre-fetch the keys on startup to ensure the identity service is reachable.
	// This makes the service fail-fast if the JWKS endpoint is misconfigured.
	_, err = cache.Refresh(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to perform initial JWKS fetch: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Debug("Auth: Failed. Missing Authorization header") // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing Authorization header")
				return
			}

			tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
			if !found {
				logger.Debug("Auth: Failed. Invalid token format, missing 'Bearer ' prefix.", "header", authHeader) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token format")
				return
			}

			// The keyfunc is called by the JWT library during parsing.
			// It fetches the key set from our cache and finds the key that
			// matches the token's `kid` (Key ID) header.
			keyFunc := func(token *jwt.Token) (interface{}, error) {
				keySet, err := cache.Get(r.Context(), jwksURL)
				if err != nil {
					return nil, fmt.Errorf("failed to get key set from cache: %w", err)
				}

				keyID, ok := token.Header["kid"].(string)
				if !ok {
					return nil, fmt.Errorf("token missing 'kid' header")
				}

				key, found := keySet.LookupKeyID(keyID)
				if !found {
					return nil, fmt.Errorf("key with ID '%s' not found in JWKS", keyID)
				}

				var rawKey interface{}
				if err := key.Raw(&rawKey); err != nil {
					return nil, fmt.Errorf("failed to get raw public key: %w", err)
				}
				return rawKey, nil
			}

			// Parse the token, providing our keyfunc to find the correct public key.
			// We now explicitly require the RS256 signing method.
			token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256"}))

			if err != nil {
				logger.Debug("Auth: Failed. Token parsing/validation error", "err", err, "token", tokenString) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, fmt.Sprintf("Unauthorized: Invalid token (%s)", err.Error()))
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				userID, ok := claims["sub"].(string)
				if !ok || userID == "" {
					logger.Debug("Auth: Failed. Token valid but 'sub' claim is missing or empty.", "claims", claims) // ADDED
					response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid user ID in token")
					return
				}

				logger.Debug("Auth: Success", "user", userID) // ADDED
				ctx := context.WithValue(r.Context(), userContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				logger.Debug("Auth: Failed. Token claims were invalid or token was not valid", "claims", claims) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token claims")
			}
		})
	}, nil
}

func NewJWKSWebsocketAuthMiddleware(jwksURL string, logger *slog.Logger) (func(http.Handler) http.Handler, error) { // CHANGED
	// Create a new, *separate* JWK cache for this middleware.
	// This avoids refactoring and keeps the changes isolated.
	cache := jwk.NewCache(context.Background())
	err := cache.Register(jwksURL, jwk.WithRefreshInterval(15*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL for WebSocket: %w", err)
	}

	// Pre-fetch the keys on startup, just like the original middleware.
	_, err = cache.Refresh(context.Background(), jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to perform initial JWKS fetch for WebSocket: %w", err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// --- The *ONLY* logic change is here ---
			tokenString := r.Header.Get("Sec-WebSocket-Protocol")
			if tokenString == "" {
				logger.Debug("WS Auth: Failed. Missing Sec-WebSocket-Protocol header.") // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing Sec-WebSocket-Protocol header")
				return
			}
			// --- End logic change ---

			keyFunc := func(token *jwt.Token) (interface{}, error) {
				keySet, err := cache.Get(r.Context(), jwksURL)
				if err != nil {
					return nil, fmt.Errorf("failed to get key set from cache: %w", err)
				}
				keyID, ok := token.Header["kid"].(string)
				if !ok {
					return nil, fmt.Errorf("token missing 'kid' header")
				}
				key, found := keySet.LookupKeyID(keyID)
				if !found {
					return nil, fmt.Errorf("key with ID '%s' not found in JWKS", keyID)
				}
				var rawKey interface{}
				if err := key.Raw(&rawKey); err != nil {
					return nil, fmt.Errorf("failed to get raw public key: %w", err)
				}
				return rawKey, nil
			}

			token, err := jwt.Parse(tokenString, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
			if err != nil {
				logger.Debug("WS Auth: Failed. Token parsing/validation error", "err", err, "token", tokenString) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, fmt.Sprintf("Unauthorized: Invalid token (%s)", err.Error()))
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				userID, ok := claims["sub"].(string)
				if !ok || userID == "" {
					logger.Debug("WS Auth: Failed. Token valid but 'sub' claim is missing or empty", "claims", claims) // ADDED
					response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid user ID in token")
					return
				}
				logger.Debug("WS Auth: Success", "user", userID) // ADDED
				ctx := ContextWithUserID(r.Context(), userID)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				logger.Debug("WS Auth: Failed. Token claims were invalid or token was not valid", "claims", claims) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token claims")
			}
		})
	}, nil
}

// DEPRECATED: NewLegacySharedSecretAuthMiddleware uses a symmetric HS256 shared secret for JWT validation.
// This pattern is less secure as it requires sharing the secret with all services.
// It is retained for backward compatibility only and should NOT be used for new services.
// Use NewJWKSAuthMiddleware instead.
func NewLegacySharedSecretAuthMiddleware(jwtSecret string, logger *slog.Logger) func(http.Handler) http.Handler { // CHANGED
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Debug("Auth (Legacy): Failed. Missing Authorization header") // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing Authorization header")
				return
			}

			tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
			if !found {
				logger.Debug("Auth (Legacy): Failed. Invalid token format, missing 'Bearer ' prefix.", "header", authHeader) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token format")
				return
			}

			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(jwtSecret), nil
			})

			if err != nil {
				logger.Debug("Auth (Legacy): Failed. Token parsing/validation error", "err", err, "token", tokenString) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token")
				return
			}

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				userID, ok := claims["sub"].(string)
				if !ok || userID == "" {
					logger.Debug("Auth (Legacy): Failed. Token valid but 'sub' claim is missing or empty", "claims", claims) // ADDED
					response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid user ID in token")
					return
				}

				logger.Debug("Auth (Legacy): Success", "user", userID) // ADDED
				ctx := context.WithValue(r.Context(), userContextKey, userID)
				next.ServeHTTP(w, r.WithContext(ctx))
			} else {
				logger.Debug("Auth (Legacy): Failed. Token claims were invalid or token was not valid", "claims", claims) // ADDED
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token claims")
			}
		})
	}
}

// GetUserIDFromContext safely retrieves the user ID from the request context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userContextKey).(string)
	return userID, ok
}

// ContextWithUserID is a helper function for tests to inject a user ID
// into a context, simulating a successful authentication.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userContextKey, userID)
}
