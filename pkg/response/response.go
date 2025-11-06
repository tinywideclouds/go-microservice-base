// Package response provides helper functions for writing standardized API responses.
package response

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// APIError represents a standard JSON error response.
type APIError struct {
	Error string `json:"error"`
}

// WriteJSON writes a JSON response with the given status code and payload.
func WriteJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if payload == nil {
		return
	}

	err := json.NewEncoder(w).Encode(payload)
	if err != nil {
		// Log the error but don't try to write another response,
		// as the headers have already been sent.
		slog.Error("Failed to write JSON response", "err", err) // CHANGED
	}
}

// WriteJSONError writes a standardized JSON error message.
func WriteJSONError(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, APIError{Error: message})
}
