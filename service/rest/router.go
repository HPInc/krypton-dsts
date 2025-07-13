// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

func requestLogger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Calculate and report REST latency metric.
		defer metrics.ReportLatencyMetric(metrics.MetricRestLatency, start,
			r.URL.Path)

		if (debugLogRestRequests) && (r.URL.Path != "/health") {
			dump, err := httputil.DumpRequest(r, true)
			if err != nil {
				dstsLogger.Error("Error logging request!",
					zap.Error(err),
				)
				return
			}
			dstsLogger.Info("+++ New REST request +++",
				zap.ByteString("Request", dump),
			)
		}

		inner.ServeHTTP(w, r)
		if (debugLogRestRequests) && (r.URL.Path != "/health") {
			dstsLogger.Info("-- Served REST request --",
				zap.String("Method: ", r.Method),
				zap.String("Request URI: ", r.RequestURI),
				zap.String("Route name: ", name),
				zap.String("Duration: ", time.Since(start).String()),
			)
		}
	})
}

// Initializes the REST request router for the DSTS service and registers all
// routes and their corresponding handler functions.
func initRequestRouter() *mux.Router {
	router := mux.NewRouter().StrictSlash(true)

	for _, route := range registeredRoutes {
		var handler http.Handler
		handler = route.HandlerFunc
		handler = requestLogger(handler, route.Name)

		router.
			Methods(route.Method).
			Path(route.Path).
			Name(route.Name).
			Handler(handler)
	}
	return router
}
