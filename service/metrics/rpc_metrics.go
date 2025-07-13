// package github.com/HPInc/krypton-dsts/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Number of gRPC requests served by the DSTS.
	MetricRPCsServed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_requests",
			Help: "Total number of RPCs served by the DSTS",
		})

	// Number of failed gRPC requests.
	MetricRPCErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_errors",
			Help: "Total number of failed RPC requests to the DSTS",
		})

	// RPC request processing latency is partitioned by the RPC method. It uses
	// custom buckets based on the expected request duration.
	MetricRPCLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "dsts_rpc_latency_milliseconds",
			Help:       "A latency histogram for RPC requests served by the DSTS",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Number of device objects created by the DSTS.
	MetricDeviceCreated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_device_created",
			Help: "Total number of devices created by the DSTS",
		})

	// Number of enrollment token objects created by the DSTS.
	MetricEnrollmentTokenCreated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_enrollment_token_created",
			Help: "Total number of enrollment tokens created by the DSTS",
		})

	// Number of device object get requests served by the DSTS.
	MetricDeviceGet = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_device_get",
			Help: "Total number of device get requests processed by the DSTS",
		})

	// Number of enrollment token get requests served by the DSTS.
	MetricEnrollmentTokenGet = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_enrollment_token_get",
			Help: "Total number of enrollment token get requests processed by the DSTS",
		})

	// Number of list devices requests served by the DSTS.
	MetricDevicesListed = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_devices_list",
			Help: "Total number of list devices requests processed by the DSTS",
		})

	// Number of device objects deleted by the DSTS.
	MetricDeviceDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_device_deleted",
			Help: "Total number of devices deleted by the DSTS",
		})

	// Number of enrollment tokens deleted by the DSTS.
	MetricEnrollmentTokenDeleted = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_enrollment_token_deleted",
			Help: "Total number of enrollment tokens deleted by the DSTS",
		})

	// Number of enrollment tokens validated successfully by the DSTS.
	MetricEnrollmentTokenValidated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_enrollment_token_validated",
			Help: "Total number of enrollment tokens validated successfully by the DSTS",
		})

	// Number of device objects updated by the DSTS.
	MetricDeviceUpdated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_device_updated",
			Help: "Total number of devices updated by the DSTS",
		})

	// Number of bad/invalid create device requests to the DSTS.
	MetricCreateDeviceBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_device_bad_requests",
			Help: "Total number of bad create device requests to the DSTS",
		})

	// Number of bad/invalid create enrollment token requests to the DSTS.
	MetricCreateEnrollmentTokenBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_enrollment_token_bad_requests",
			Help: "Total number of bad create enrollment token requests to the DSTS",
		})

	// Number of bad/invalid get device requests to the DSTS.
	MetricGetDeviceBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_device_bad_requests",
			Help: "Total number of bad get device requests to the DSTS",
		})

	// Number of bad/invalid get enrollment token requests to the DSTS.
	MetricGetEnrollmentTokenBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_enrollment_token_bad_requests",
			Help: "Total number of bad get enrollment token requests to the DSTS",
		})

	MetricGetEnrollmentTokenNotFound = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_enrollment_token_not_found",
			Help: "Total number of get enrollment token requests where the token was not found",
		})

	// Number of bad/invalid list devices requests to the DSTS.
	MetricListDevicesBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_list_devices_bad_requests",
			Help: "Total number of bad list devices requests to the DSTS",
		})

	// Number of bad/invalid delete device requests to the DSTS.
	MetricDeleteDeviceBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_device_bad_requests",
			Help: "Total number of bad delete device requests to the DSTS",
		})

	// Number of bad/invalid delete enrollment token requests to the DSTS.
	MetricDeleteEnrollmentTokenBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_enrollment_token_bad_requests",
			Help: "Total number of bad delete enrollment token requests to the DSTS",
		})

	// Number of bad/invalid update device requests to the DSTS.
	MetricUpdateDeviceBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_update_device_bad_requests",
			Help: "Total number of bad update device requests to the DSTS",
		})

	// Number of bad/invalid validate enrollment token requests to the DSTS.
	MetricValidateEnrollmentTokenBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_validate_enrollment_token_bad_requests",
			Help: "Total number of bad validate enrollment token requests to the DSTS",
		})

	// Number of create device requests to the DSTS, resulting in internal
	// errors.
	MetricCreateDeviceInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_device_internal_errors",
			Help: "Total number of internal errors processing create device requests",
		})

	// Number of create device requests to the DSTS, resulting in already exists
	// (duplicate key) errors.
	MetricCreateDeviceAlreadyExistsErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_device_already_exists_errors",
			Help: "Total number of already exists errors processing create device requests",
		})

	// Number of create enrollment token requests to the DSTS, resulting in internal
	// errors.
	MetricCreateEnrollmentTokenInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_enrollment_token_internal_errors",
			Help: "Total number of internal errors processing create enrollment token requests",
		})

	// Number of create enrollment token requests to the DSTS, resulting in already exists
	// (duplicate key) errors.
	MetricCreateEnrollmentTokenAlreadyExistsErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_create_enrollment_token_already_exists_errors",
			Help: "Total number of already exists errors processing create enrollment token requests",
		})

	// Number of get device requests to the DSTS, resulting in internal
	// errors.
	MetricGetDeviceInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_device_internal_errors",
			Help: "Total number of internal errors processing get device requests",
		})

	MetricGetDeviceNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_device_not_found_errors",
			Help: "Total number of get device requests where the device was not found",
		})

	// Number of get enrollment token requests to the DSTS, resulting in internal
	// errors.
	MetricGetEnrollmentTokenInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_enrollment_token_internal_errors",
			Help: "Total number of internal errors processing get enrollment token requests",
		})

	// Number of validate enrollment token requests to the DSTS, resulting in
	// internal errors.
	MetricValidateEnrollmentTokenInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_validate_enrollment_token_internal_errors",
			Help: "Total number of internal errors processing validate enrollment token requests",
		})

	// Number of list devices requests to the DSTS, resulting in internal
	// errors.
	MetricListDevicesInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_list_devices_internal_errors",
			Help: "Total number of internal errors processing list device requests",
		})

	// Number of delete device requests to the DSTS, resulting in internal
	// errors.
	MetricDeleteDeviceInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_device_internal_errors",
			Help: "Total number of internal errors processing delete device requests",
		})

	MetricDeleteDeviceNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_device_not_found_errors",
			Help: "Total number of delete device requests where the device was not found",
		})

	// Number of delete enrollment token requests to the DSTS, resulting in internal
	// errors.
	MetricDeleteEnrollmentTokenInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_enrollment_token_internal_errors",
			Help: "Total number of internal errors processing delete enrollment token requests",
		})

	MetricDeleteEnrollmentTokenNotFound = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_delete_enrollment_token_not_found_errors",
			Help: "Total number of not found errors processing delete enrollment token requests",
		})

	// Number of update device requests to the DSTS, resulting in internal
	// errors.
	MetricUpdateDeviceInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_update_device_internal_errors",
			Help: "Total number of internal errors processing update device requests",
		})

	MetricUpdateDeviceNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_update_device_not_found_errors",
			Help: "Total number of update device requests where the device was not found",
		})

	// Number of validate enrollment token requests to the DSTS, resulting in access denied
	// errors.
	MetricValidateEnrollmentTokenAccessDenied = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_validate_enrollment_token_access_denied_errors",
			Help: "Total number of access denied errors processing validate enrollment token requests",
		})

	MetricValidateEnrollmentTokenServerErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_validate_enrollment_token_server_busy_errors",
			Help: "Total number of server busy errors processing validate enrollment token requests",
		})

	// Number of get signing key requests processed by the DSTS.
	MetricGetSigningKeyRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_signing_key",
			Help: "Total number of get signing key requests processed by the DSTS",
		})

	// Number of ping requests processed by the DSTS.
	MetricPingRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_ping",
			Help: "Total number of ping requests processed by the DSTS",
		})

	MetricAppAuthenticationChallenge = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_app_authn_challenge_requests",
			Help: "Total number of app authentication challenge requests processed by the DSTS",
		})

	MetricAppAuthenticationChallengeBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_app_authn_challenge_bad_requests",
			Help: "Total number of bad app authentication challenge requests processed by the DSTS",
		})

	MetricAppAuthenticationChallengeInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_get_app_authn_challenge_internal_errors",
			Help: "Total number of internal errors processing app authentication challenge requests",
		})

	MetricAppAuthenticationRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_app_authn_requests",
			Help: "Total number of app authentication requests processed by the DSTS",
		})

	MetricAppAuthenticationBadRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_app_authn_bad_requests",
			Help: "Total number of bad app authentication requests processed by the DSTS",
		})

	MetricAppAuthenticationInternalErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_app_authn_internal_errors",
			Help: "Total number of internal errors processing app authentication requests",
		})

	MetricAppAuthenticationUnauthorizedErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_rpc_app_authn_unauthorized_errors",
			Help: "Total number of unauthorized errors processing app authentication requests",
		})
)
