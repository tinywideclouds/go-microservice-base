package middleware_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tinywideclouds/go-microservice-base/pkg/middleware"
)

// TestContextHelpers verifies that our helper function correctly injects
// all identity fields into the context, and the getters retrieve them.
func TestContextHelpers(t *testing.T) {
	// Arrange
	userID := "urn:auth:google:123"
	handle := "urn:lookup:email:bob@test.com"
	email := "bob@test.com"

	// Act
	// We use the new helper that injects everything
	ctx := middleware.ContextWithUser(context.Background(), userID, handle, email)

	// Assert
	gotUserID, ok := middleware.GetUserIDFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, userID, gotUserID)

	gotHandle, ok := middleware.GetUserHandleFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, handle, gotHandle)

	gotEmail, ok := middleware.GetUserEmailFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, email, gotEmail)
}
