package microservice_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinywideclouds/go-microservice-base/pkg/microservice"
)

func TestBaseServer_LifecycleAndProbes(t *testing.T) {
	logger := zerolog.Nop()
	server := microservice.NewBaseServer(logger, ":0")

	var wg sync.WaitGroup
	wg.Add(1)
	readyChan := make(chan struct{})
	server.SetReadyChannel(readyChan)

	go func() {
		defer wg.Done()
		err := server.Start()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server.Start() returned an unexpected error: %v", err)
		}
	}()

	select {
	case <-readyChan:
		t.Log("Server is confirmed to be listening.")
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out waiting for server to start")
	}

	serverURL := "http://127.0.0.1" + server.GetHTTPPort()

	// 1. Test /healthz endpoint
	resp, err := http.Get(serverURL + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "OK", string(body))

	// 2. Test initial /readyz state (should be NOT READY)
	resp, err = http.Get(serverURL + "/readyz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "NOT READY", string(body))

	// 3. Mark the server as ready and test /readyz again
	server.SetReady(true)
	resp, err = http.Get(serverURL + "/readyz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "READY", string(body))

	// 4. Test /metrics endpoint (just check for 200 OK)
	resp, err = http.Get(serverURL + "/metrics")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	// 5. Test shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = server.Shutdown(shutdownCtx)
	require.NoError(t, err)

	wg.Wait()
	t.Log("Server shutdown confirmed.")
}
