package microservice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/VictoriaMetrics/metrics"
)

// BaseConfig holds common configuration fields for all services.
type BaseConfig struct {
	LogLevel           string `yaml:"log_level"`
	HTTPPort           string `yaml:"http_port"`
	ProjectID          string `yaml:"project_id"`
	CredentialsFile    string `yaml:"credentials_file"`
	ServiceName        string `yaml:"service_name"`
	DataflowName       string `yaml:"dataflow_name"`
	ServiceDirectorURL string `yaml:"service_director_url"`
}

// Service defines the common interface for all microservices.
type Service interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	Mux() *http.ServeMux
	GetHTTPPort() string
}

// BaseServer provides common functionalities for microservice servers, including
// lifecycle management, graceful shutdown, and standard observability endpoints.
type BaseServer struct {
	Logger     *slog.Logger
	HTTPPort   string
	httpServer *http.Server
	mux        *http.ServeMux
	actualAddr string
	mu         sync.RWMutex
	readyChan  chan struct{}
	isReady    *atomic.Value
}

// NewBaseServer creates and initializes a new BaseServer.
// It automatically registers the following reserved observability paths:
//   - /healthz: Liveness probe
//   - /readyz: Readiness probe
//   - /metrics: Prometheus metrics (via VictoriaMetrics)
func NewBaseServer(logger *slog.Logger, httpPort string) *BaseServer {
	mux := http.NewServeMux()

	listenAddr := httpPort
	if listenAddr == "" {
		listenAddr = "8080"
	}
	if !strings.HasPrefix(listenAddr, ":") {
		listenAddr = ":" + listenAddr
	}

	isReady := &atomic.Value{}
	isReady.Store(false)

	s := &BaseServer{
		Logger:   logger,
		HTTPPort: listenAddr,
		mux:      mux,
		isReady:  isReady,
	}
	s.httpServer = &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	s.registerDefaultHandlers()
	return s
}

func (s *BaseServer) registerDefaultHandlers() {
	s.mux.HandleFunc("/healthz", s.healthzHandler)
	s.mux.HandleFunc("/readyz", s.readyzHandler)

	// Expose metrics using the lightweight VictoriaMetrics handler.
	s.mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		metrics.WritePrometheus(w, true)
	})
}

// SetReadyChannel allows the consuming service to provide a channel that will be closed
// when the HTTP server effectively starts listening on the TCP port.
func (s *BaseServer) SetReadyChannel(ch chan struct{}) {
	s.readyChan = ch
}

// SetReady allows the consuming service to signal that it is ready to serve traffic.
// This controls the status code of the /readyz endpoint.
func (s *BaseServer) SetReady(ready bool) {
	s.isReady.Store(ready)
	if ready {
		s.Logger.Info("Service has been marked as READY.")
	} else {
		s.Logger.Warn("Service has been marked as NOT READY.")
	}
}

// Start is a blocking call that starts the HTTP server.
// It returns only when the server is closed or fails to start.
func (s *BaseServer) Start() error {
	listener, err := net.Listen("tcp", s.HTTPPort)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", s.HTTPPort, err)
	}

	s.mu.Lock()
	s.actualAddr = listener.Addr().String()
	s.mu.Unlock()

	s.Logger.Info("HTTP server starting to listen", "address", s.actualAddr)

	if s.readyChan != nil {
		s.Logger.Debug("Closing ready channel to signal listener is active.")
		close(s.readyChan)
	}

	if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.Logger.Error("HTTP server failed", "err", err)
		return err
	}

	s.Logger.Info("HTTP server has stopped listening.")
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *BaseServer) Shutdown(ctx context.Context) error {
	s.Logger.Info("Shutting down HTTP server...")
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.Logger.Error("Error during HTTP server shutdown.", "err", err)
		return err
	}
	s.Logger.Info("HTTP server stopped.")
	return nil
}

// GetHTTPPort returns the actual network port the server is listening on.
func (s *BaseServer) GetHTTPPort() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, port, err := net.SplitHostPort(s.actualAddr)
	if err != nil {
		return s.HTTPPort
	}
	return ":" + port
}

// Mux returns the underlying ServeMux for registering additional handlers.
// Note: Do not register paths that collide with standard observability endpoints.
func (s *BaseServer) Mux() *http.ServeMux {
	return s.mux
}

func (s *BaseServer) healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *BaseServer) readyzHandler(w http.ResponseWriter, _ *http.Request) {
	if s.isReady.Load().(bool) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("READY"))
		return
	}

	s.Logger.Debug("Readiness probe failed: service is not ready.")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("NOT READY"))
}
