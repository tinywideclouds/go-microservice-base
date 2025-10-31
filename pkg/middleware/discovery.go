package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

// OIDCDiscoveryConfig holds the fields we care about from an identity service's metadata.
type OIDCDiscoveryConfig struct {
	Issuer        string   `json:"issuer"`
	JWKS_URI      string   `json:"jwks_uri"`
	SupportedAlgs []string `json:"id_token_signing_alg_values_supported"`
}

// DiscoverAndValidateJWTConfig fetches metadata from an OIDC-compatible discovery endpoint,
// validates that a required JWT signing algorithm is supported, and returns the discovered JWKS URI.
// This is a critical startup check for any microservice acting as a resource server.
func DiscoverAndValidateJWTConfig(identityServiceURL string, requiredAlg string, logger zerolog.Logger) (string, error) {
	logger.Info().Str("identity_service_url", identityServiceURL).Msg("Discovering configuration from identity service")
	metadataURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", identityServiceURL)

	resp, err := http.Get(metadataURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch metadata from %s: %w", metadataURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code (%d) from metadata endpoint", resp.StatusCode)
	}

	var config OIDCDiscoveryConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return "", fmt.Errorf("failed to decode identity service metadata: %w", err)
	}

	isAlgSupported := false
	for _, alg := range config.SupportedAlgs {
		if alg == requiredAlg {
			isAlgSupported = true
			break
		}
	}

	if !isAlgSupported {
		return "", fmt.Errorf(
			"identity service no longer supports the required JWT algorithm '%s'. Supported algorithms: %v",
			requiredAlg, config.SupportedAlgs,
		)
	}

	logger.Info().Msg("SUCCESS: JWT algorithm policies are compatible.")
	return config.JWKS_URI, nil
}
