// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

var (
	dstsLogger           *zap.Logger
	debugLogRestRequests bool
)

const (
	// HTTP server timeouts for the REST endpoint.
	readTimeout        = (time.Second * 5)
	writeTimeout       = (time.Second * 5)
	defaultIdleTimeout = (time.Second * 65)
)

type dstsRestService struct {
	// Signal handling to support SIGTERM and SIGINT for the service.
	errChannel  chan error
	stopChannel chan os.Signal

	router *mux.Router
	port   int
}

func newDstsRestService() *dstsRestService {
	s := &dstsRestService{}

	// Initial signal handling.
	s.errChannel = make(chan error)
	s.stopChannel = make(chan os.Signal, 1)
	signal.Notify(s.stopChannel, syscall.SIGINT, syscall.SIGTERM)

	s.router = initRequestRouter()
	return s
}

func (s *dstsRestService) startServing() {
	// Start the HTTP REST server. http.ListenAndServe() always returns
	// a non-nil error
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", s.port),
		Handler:        s.router,
		ReadTimeout:    readTimeout,
		WriteTimeout:   writeTimeout,
		IdleTimeout:    defaultIdleTimeout,
		MaxHeaderBytes: 1 << 20,
	}

	err := server.ListenAndServe()
	dstsLogger.Error("Received a fatal error from http.ListenAndServe",
		zap.Error(err),
	)

	// Signal the error channel so we can shutdown the service.
	s.errChannel <- err
}

func (s *dstsRestService) awaitTermination() {
	select {
	case err := <-s.errChannel:
		dstsLogger.Error("Shutting down due to a fatal error.",
			zap.Error(err),
		)
	case sig := <-s.stopChannel:
		dstsLogger.Info("Received an OS signal to shut down!",
			zap.String("Signal received: ", sig.String()),
		)
	}
}

func Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) {
	dstsLogger = logger
	debugLogRestRequests = cfgMgr.IsDebugLoggingRestRequestsEnabled()

	s := newDstsRestService()
	s.port = cfgMgr.GetServerConfig().RestPort

	// Initialize the REST server and listen for REST requests on a separate
	// goroutine. Report fatal errors via the error channel.
	go s.startServing()
	dstsLogger.Info("Started the DSTS REST service!",
		zap.Int("Port: ", s.port),
	)

	s.awaitTermination()
}

func InitTestServer(logger *zap.Logger, cfgMgr *config.ConfigMgr) {
	dstsLogger = logger
	debugLogRestRequests = cfgMgr.IsDebugLoggingRestRequestsEnabled()
}

func ExecuteTestRequest(r *http.Request,
	handler http.HandlerFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router := initRequestRouter()
	router.ServeHTTP(rec, r)
	return rec
}
