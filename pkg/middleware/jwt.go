package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"
)

// contextKey is a private type to prevent collisions with other context keys.
type contextKey string

const (
	userContextKey    contextKey = "userID"
	handleContextKey  contextKey = "userHandle" // The lookup URN (e.g. urn:lookup:email:...)
	emailContextKey   contextKey = "userEmail"
	nameContextKey    contextKey = "userName"
	pictureContextKey contextKey = "userPicture"
)

// JWTSigningMethod represents allowed signing algorithms.
type JWTSigningMethod string

// RSA256 is the default signing method required by this library.
const RSA256 JWTSigningMethod = "RS256"

// JWKSManager defines the interface for a key set manager.
type JWKSManager jwk.Set

// NewJWKSManager creates a new, auto-refreshing JWKS key set from a remote URL.
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

// NoopAuth is a test helper that bypasses all auth checks.
// It injects a static user ID into the request context if enabled.
func NoopAuth(enabled bool, staticUserID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				response.WriteJSONError(w, http.StatusUnauthorized, "Auth is disabled by test")
				return
			}
			ctx := ContextWithUserID(r.Context(), staticUserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// NewJWKSAuthMiddleware creates a JWT authentication middleware that validates RS256 tokens via JWKS.
func NewJWKSAuthMiddleware(jwksURL string, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	cache, err := setupJWKSCache(jwksURL)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Debug("Auth: Failed. Missing Authorization header")
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing Authorization header")
				return
			}

			tokenString, found := strings.CutPrefix(authHeader, "Bearer ")
			if !found {
				logger.Debug("Auth: Failed. Invalid token format, missing 'Bearer ' prefix.", "header", authHeader)
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Invalid token format")
				return
			}

			ctx, err := validateTokenAndGetContext(r.Context(), tokenString, cache, jwksURL, logger)
			if err != nil {
				logger.Debug("Auth: Validation failed", "err", err)
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

// NewJWKSWebsocketAuthMiddleware creates a JWT authentication middleware for WebSockets.
// It expects the token to be in the "Sec-WebSocket-Protocol" header.
func NewJWKSWebsocketAuthMiddleware(jwksURL string, logger *slog.Logger) (func(http.Handler) http.Handler, error) {
	cache, err := setupJWKSCache(jwksURL)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenString := r.Header.Get("Sec-WebSocket-Protocol")
			if tokenString == "" {
				logger.Debug("WS Auth: Failed. Missing Sec-WebSocket-Protocol header.")
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: Missing Sec-WebSocket-Protocol header")
				return
			}

			ctx, err := validateTokenAndGetContext(r.Context(), tokenString, cache, jwksURL, logger)
			if err != nil {
				logger.Debug("WS Auth: Validation failed", "err", err)
				response.WriteJSONError(w, http.StatusUnauthorized, "Unauthorized: "+err.Error())
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

// setupJWKSCache initializes the JWK cache and pre-fetches keys.
func setupJWKSCache(jwksURL string) (*jwk.Cache, error) {
	cache := jwk.NewCache(context.Background())
	err := cache.Register(jwksURL, jwk.WithRefreshInterval(15*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	if _, err = cache.Refresh(context.Background(), jwksURL); err != nil {
		return nil, fmt.Errorf("failed to perform initial JWKS fetch: %w", err)
	}
	return cache, nil
}

// validateTokenAndGetContext handles the shared logic of parsing the token,
// verifying the signature against the cached JWKS, and extracting claims into a new Context.
func validateTokenAndGetContext(ctx context.Context, tokenString string, cache *jwk.Cache, jwksURL string, logger *slog.Logger) (context.Context, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		keySet, err := cache.Get(ctx, jwksURL)
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
		return nil, fmt.Errorf("invalid token (%s)", err.Error())
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["sub"].(string)
		if !ok || userID == "" {
			return nil, fmt.Errorf("invalid user ID in token")
		}

		handle, _ := claims["handle"].(string)
		email, _ := claims["email"].(string)
		name, _ := claims["name"].(string)
		picture, _ := claims["picture"].(string)

		logger.Debug("Auth: Success", "user", userID, "handle", handle)

		newCtx := context.WithValue(ctx, userContextKey, userID)
		if handle != "" {
			newCtx = context.WithValue(newCtx, handleContextKey, handle)
		}
		if email != "" {
			newCtx = context.WithValue(newCtx, emailContextKey, email)
		}
		if name != "" {
			newCtx = context.WithValue(newCtx, nameContextKey, name)
		}
		if picture != "" {
			newCtx = context.WithValue(newCtx, pictureContextKey, picture)
		}
		return newCtx, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetUserIDFromContext safely retrieves the user ID from the request context.
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userContextKey).(string)
	return userID, ok
}

// GetUserHandleFromContext safely retrieves the lookup URN (Handle) from the request context.
func GetUserHandleFromContext(ctx context.Context) (string, bool) {
	handle, ok := ctx.Value(handleContextKey).(string)
	return handle, ok
}

// GetUserEmailFromContext safely retrieves the user email from the request context.
func GetUserEmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailContextKey).(string)
	return email, ok
}

// ContextWithUserID is a helper function for tests to inject a user ID.
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userContextKey, userID)
}

// ContextWithUser is a helper function for tests to inject a full user context.
func ContextWithUser(ctx context.Context, userID, handle, email string) context.Context {
	ctx = context.WithValue(ctx, userContextKey, userID)
	if handle != "" {
		ctx = context.WithValue(ctx, handleContextKey, handle)
	}
	if email != "" {
		ctx = context.WithValue(ctx, emailContextKey, email)
	}
	return ctx
}
