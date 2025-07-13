// package github.com/HPInc/krypton-dsts/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Database request processing latency is partitioned by the Postgres method. It uses
	// custom buckets based on the expected request duration.
	MetricDatabaseLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "dsts_db_latency_milliseconds",
			Help:       "A latency histogram for database operations issued by the DSTS",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Total number of errors committing database transactions.
	MetricDatabaseCommitErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_commit_errors",
			Help: "Total number of errors committing transactions",
		})

	// Total number of errors rolling back database transactions.
	MetricDatabaseRollbackErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_rollback_errors",
			Help: "Total number of errors rolling back transactions",
		})

	// Total number of failed database create device operations.
	MetricDatabaseCreateDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_create_device_failures",
			Help: "Total number of failed create device database operations",
		})

	// Total number of failed database create enrollment token operations.
	MetricDatabaseCreateEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_create_enrollment_token_failures",
			Help: "Total number of failed create enrollment token database operations",
		})

	// Total number of failed database get device operations.
	MetricDatabaseGetDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_get_device_failures",
			Help: "Total number of failed get device database operations",
		})

	MetricDatabaseGetTombstonedDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_get_tombstoned_device_failures",
			Help: "Total number of failed get tombstoned device database operations",
		})

	// Total number of failed database get enrollment token operations.
	MetricDatabaseGetEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_get_enrollment_token_failures",
			Help: "Total number of failed get enrollment token database operations",
		})

	// Total number of failed database list devices operations.
	MetricDatabaseListDevicesFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_list_devices_failures",
			Help: "Total number of failed list devices database operations",
		})

	// Total number of failed database update device operations.
	MetricDatabaseUpdateDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_update_device_failures",
			Help: "Total number of failed update device database operations",
		})

	// Total number of failed database delete device operations.
	MetricDatabaseDeleteDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_delete_device_failures",
			Help: "Total number of failed delete device database operations",
		})

	// Total number of failed database delete enrollment token operations.
	MetricDatabaseDeleteEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_delete_enrollment_token_failures",
			Help: "Total number of failed delete enrollment token database operations",
		})

	// Total number of devices created in the database.
	MetricDatabaseDevicesCreated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_devices_created",
			Help: "Total number of devices created in the database",
		})

	// Total number of enrollment tokens created in the database.
	MetricDatabaseEnrollmentTokensCreated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_enrollment_tokens_created",
			Help: "Total number of enrollment tokens created in the database",
		})

	// Total number of devices retrieved from the database.
	MetricDatabaseDevicesRetrieved = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_devices_retrieved",
			Help: "Total number of devices retrieved from the database",
		})

	// Total number of enrollment tokens retrieved from the database.
	MetricDatabaseEnrollmentTokensRetrieved = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_enrollment_tokens_retrieved",
			Help: "Total number of enrollment tokens retrieved from the database",
		})

	// Total number of devices updated in the database.
	MetricDatabaseDevicesUpdated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_devices_updated",
			Help: "Total number of devices updated in the database",
		})

	// Total number of enrollment tokens updated in the database.
	MetricDatabaseEnrollmentTokensUpdated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_enrollment_tokens_updated",
			Help: "Total number of enrollment tokens updated in the database",
		})

	// Total number of devices deleted from the database.
	MetricDatabaseDevicesDeleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_devices_deleted",
			Help: "Total number of devices deleted from the database",
		})

	// Total number of enrollment tokens deleted from the database.
	MetricDatabaseEnrollmentTokensDeleted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_enrollment_tokens_deleted",
			Help: "Total number of enrollment tokens deleted from the database",
		})

	// Total number of times the requested device was not found in the database.
	MetricDatabaseDeviceNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_device_not_found_errors",
			Help: "Total number of times device was not found in database",
		})

	MetricDatabaseTombstonedDeviceNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_get_tombstoned_device_failures",
			Help: "Total number of failed get tombstoned device database operations",
		})

	// Total number of times the requested enrollment token was not found in the
	// database.
	MetricDatabaseEnrollmentTokenNotFoundErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_db_enrollment_token_not_found_errors",
			Help: "Total number of times enrollment token was not found in database",
		})
)
