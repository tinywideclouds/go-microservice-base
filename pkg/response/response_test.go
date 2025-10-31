package response_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-microservice-base/pkg/response"
)

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	payload := map[string]string{"message": "success"}

	response.WriteJSON(rr, http.StatusOK, payload)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var actualPayload map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &actualPayload)
	require.NoError(t, err)
	assert.Equal(t, payload, actualPayload)
}

func TestWriteJSONError(t *testing.T) {
	rr := httptest.NewRecorder()
	errorMessage := "resource not found"

	response.WriteJSONError(rr, http.StatusNotFound, errorMessage)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var actualError response.APIError
	err := json.Unmarshal(rr.Body.Bytes(), &actualError)
	require.NoError(t, err)
	assert.Equal(t, errorMessage, actualError.Error)
}
