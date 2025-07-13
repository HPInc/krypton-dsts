// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Route - used to route REST requests received by the service.
type Route struct {
	Name        string           // Name of the route
	Method      string           // REST method
	Path        string           // Resource path
	HandlerFunc http.HandlerFunc // Request handler function.
}

type routes []Route

// List of Routes and corresponding handler functions registered
// with the router.
var registeredRoutes = routes{
	// Health method.
	Route{
		Name:        "GetHealth",
		Method:      http.MethodGet,
		Path:        "/health",
		HandlerFunc: GetHealthHandler,
	},

	// Metrics method.
	Route{
		Name:        "GetMetrics",
		Method:      http.MethodGet,
		Path:        "/metrics",
		HandlerFunc: promhttp.Handler().(http.HandlerFunc),
	},

	// Signing key method.
	Route{
		Name:        "GetSigningKey",
		Method:      http.MethodGet,
		Path:        "/api/v1/keys",
		HandlerFunc: GetSigningKeyHandler,
	},

	// Device authentication methods.
	Route{
		Name:        "DeviceAuthChallenge",
		Method:      http.MethodGet,
		Path:        "/api/v1/deviceauth/challenge",
		HandlerFunc: DeviceAuthenticationChallengeHandler,
	},
	Route{
		Name:        "DeviceAuthToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/deviceauth/token",
		HandlerFunc: DeviceAuthenticationHandler,
	},
	// App authentication methods.
	Route{
		Name:        "AppAuthChallenge",
		Method:      http.MethodGet,
		Path:        "/api/v1/appauth/challenge",
		HandlerFunc: AppAuthenticationChallengeHandler,
	},
	Route{
		Name:        "AppAuthToken",
		Method:      http.MethodPost,
		Path:        "/api/v1/appauth/token",
		HandlerFunc: AppAuthenticationHandler,
	},
}
