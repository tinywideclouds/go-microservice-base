package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// OIDCDiscoveryConfig holds the fields we care about from an identity service's metadata.
type OIDCDiscoveryConfig struct {
	Issuer        string             `json:"issuer"`
	JWKS_URI      string             `json:"jwks_uri"`
	SupportedAlgs []JWTSigningMethod `json:"id_token_signing_alg_values_supported"`
}

// DiscoverAndValidateJWTConfig fetches metadata from an OIDC-compatible discovery endpoint,
// validates that a required JWT signing algorithm is supported, and returns the discovered JWKS URI.
func DiscoverAndValidateJWTConfig(identityServiceURL string, requiredAlg JWTSigningMethod, logger *slog.Logger) (string, error) {
	logger.Info("Discovering configuration from identity service", "identity_service_url", identityServiceURL)
	metadataURL := fmt.Sprintf("%s/.well-known/oauth-authorization-server", identityServiceURL)

	resp, err := http.Get(metadataURL)
	if err != nil {
		logger.Error("Failed to fetch OIDC metadata", "url", metadataURL, "err", err)
		return "", fmt.Errorf("failed to fetch metadata from %s: %w", metadataURL, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		logger.Warn("Received non-200 status from OIDC metadata endpoint", "url", metadataURL, "status_code", resp.StatusCode)
		return "", fmt.Errorf("received non-200 status code (%d) from metadata endpoint", resp.StatusCode)
	}

	var config OIDCDiscoveryConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		logger.Error("Failed to decode OIDC metadata", "url", metadataURL, "err", err)
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
		logger.Warn(
			"Identity service does not support required JWT algorithm",
			"required_alg", requiredAlg,
			"supported_algs", config.SupportedAlgs,
		)
		return "", fmt.Errorf(
			"identity service no longer supports the required JWT algorithm '%s'. Supported algorithms: %v",
			requiredAlg, config.SupportedAlgs,
		)
	}

	logger.Info("SUCCESS: JWT algorithm policies are compatible.")
	return config.JWKS_URI, nil
}
