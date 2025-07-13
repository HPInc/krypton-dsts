// package github.com/HPInc/krypton-dsts/service/metrics
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// Cache request processing latency is partitioned by the Redis method. It uses
	// custom buckets based on the expected request duration.
	MetricCacheLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "dsts_cache_latency_milliseconds",
			Help:       "A latency histogram for cache operations issued by the DSTS",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"method"},
	)

	// Total number of failed cache set device operations.
	MetricCacheSetDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_set_device_failures",
			Help: "Total number of failed cache set device operations",
		})

	// Total number of failed cache set enrollment token operations.
	MetricCacheSetEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_set_enrollment_token_failures",
			Help: "Total number of failed cache set enrollment token operations",
		})

	// Total number of failed cache set challenge operations.
	MetricCacheSetChallengeFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_set_challenge_failures",
			Help: "Total number of failed cache set challenge operations",
		})

	// Total number of failed cache get device operations.
	MetricCacheGetDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_device_failures",
			Help: "Total number of failed cache get device operations",
		})

	// Total number of failed cache get enrollment token operations.
	MetricCacheGetEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_enrollment_token_failures",
			Help: "Total number of failed cache get enrollment token operations",
		})

	// Total number of failed cache get challenge operations.
	MetricCacheGetChallengeFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_challenge_failures",
			Help: "Total number of failed cache get challenge operations",
		})

	// Total number of cache hits for get device operations.
	MetricCacheGetDeviceCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_device_cache_hits",
			Help: "Total number of cache hits for get device operations",
		})

	// Total number of cache hits for get app operations.
	MetricCacheGetAppCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_app_cache_hits",
			Help: "Total number of cache hits for get app operations",
		})

	// Total number of cache misses for get device operations.
	MetricCacheGetDeviceCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_device_cache_misses",
			Help: "Total number of cache misses for get device operations",
		})

	// Total number of cache misses for get app operations.
	MetricCacheGetAppCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_app_cache_misses",
			Help: "Total number of cache misses for get app operations",
		})

	// Total number of cache hits for get enrollment token operations.
	MetricCacheGetEnrollmentTokenCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_enrollment_token_cache_hits",
			Help: "Total number of cache hits for get enrollment token operations",
		})

	// Total number of cache misses for get enrollment token operations.
	MetricCacheGetEnrollmentTokenCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_enrollment_token_cache_misses",
			Help: "Total number of cache misses for get enrollment token operations",
		})

	// Total number of cache hits for get challenge operations.
	MetricCacheGetChallengeCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_challenge_cache_hits",
			Help: "Total number of cache hits for get challenge operations",
		})

	// Total number of cache misses for get challenge operations.
	MetricCacheGetChallengeCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_get_challenge_cache_misses",
			Help: "Total number of cache misses for get challenge operations",
		})

	// Total number of failed cache delete device operations.
	MetricCacheDelDeviceFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_del_device_failures",
			Help: "Total number of failed cache delete device operations",
		})

	// Total number of failed cache delete app operations.
	MetricCacheDelAppFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_del_app_failures",
			Help: "Total number of failed cache delete app operations",
		})

	// Total number of failed cache delete enrollment token operations.
	MetricCacheDelEnrollmentTokenFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dsts_cache_del_enrollment_token_failures",
			Help: "Total number of failed cache delete enrollment token operations",
		})
)
