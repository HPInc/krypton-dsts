// package github.com/HPInc/krypton-dsts/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// REST request processing latency is partitioned by the RPC method. It uses
	// custom buckets based on the expected request duration.
	MetricRestLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "dsts_rest_latency_milliseconds",
			Help:       "A latency histogram for REST requests served by the DSTS",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Number of device authentication challenge responses sent successfully by the DSTS.
	MetricDeviceAuthChallengeResponses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_challenge_requests",
			Help: "Total number of successful device authentication challenge requests processed by the DSTS",
		})

	// Number of app authentication challenge responses sent successfully by the DSTS.
	MetricAppAuthChallengeResponses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_challenge_requests",
			Help: "Total number of successful app authentication challenge requests processed by the DSTS",
		})

	// Number of device authentication responses sent successfully by the DSTS.
	MetricDeviceAuthResponses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_requests",
			Help: "Total number of successful device authentication requests processed by the DSTS",
		})

	// Number of app authentication responses sent successfully by the DSTS.
	MetricAppAuthResponses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_requests",
			Help: "Total number of successful app authentication requests processed by the DSTS",
		})

	// Number of bad/invalid device authentication challenge requests to the DSTS.
	MetricDeviceAuthChallengeBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_challenge_bad_requests",
			Help: "Total number of bad device authentication challenge requests to the DSTS",
		})

	// Number of bad/invalid app authentication challenge requests to the DSTS.
	MetricAppAuthChallengeBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_challenge_bad_requests",
			Help: "Total number of bad app authentication challenge requests to the DSTS",
		})

	// Number of bad/invalid device authentication requests to the DSTS.
	MetricDeviceAuthBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_bad_requests",
			Help: "Total number of bad device authentication requests to the DSTS",
		})

	// Number of bad/invalid app authentication requests to the DSTS.
	MetricAppAuthBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_bad_requests",
			Help: "Total number of bad app authentication requests to the DSTS",
		})

	MetricDeviceAuthBlocked = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_blocked",
			Help: "Total number of device authentication requests blocked for lost/disabled devices",
		})

	// Number of device authentication challenge requests resulting in internal errors.
	MetricDeviceAuthChallengeInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_challenge_internal_errors",
			Help: "Total number of internal errors processing device authentication challenge requests to the DSTS",
		})

	// Number of app authentication challenge requests resulting in internal errors.
	MetricAppAuthChallengeInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_challenge_internal_errors",
			Help: "Total number of internal errors processing app authentication challenge requests to the DSTS",
		})

	// Number of device authentication requests resulting in internal errors.
	MetricDeviceAuthInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_device_auth_internal_errors",
			Help: "Total number of internal errors processing device authentication requests to the DSTS",
		})

	// Number of app authentication requests resulting in internal errors.
	MetricAppAuthInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_internal_errors",
			Help: "Total number of internal errors processing app authentication requests to the DSTS",
		})

	MetricAppAuthBlocked = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rest_app_auth_blocked",
			Help: "Total number of app authentication requests blocked for disabled apps",
		})
)
