// package github.com/HPInc/krypton-dsts/service/cache
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// AddEnrollmentToken - Add a new enrollment token object to the cache.
func AddEnrollmentToken(requestID string, token string,
	enrollment_token interface{}) {
	if !isEnabled {
		return
	}

	// Marshal the enrollment token object for caching.
	cacheEntry, err := json.Marshal(enrollment_token)
	if err != nil {
		dstsLogger.Error("Failed to marshal enrollment token for caching!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		return
	}

	// Add the enrollment token to the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err = cacheClient.Set(ctx, fmt.Sprintf(enrollTokenPrefix, token),
		cacheEntry, ttlDevice).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheSet)
	if err != nil {
		dstsLogger.Error("Failed to add the enrollment token to the cache!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		metrics.MetricCacheSetEnrollmentTokenFailures.Inc()
	}
}

// GetEnrollmentToken - retrieve information about an enrollment token object
// from the cache.
func GetEnrollmentTokenInfo(requestID string, token string) ([]byte, error) {
	if !isEnabled {
		return nil, ErrCacheNotFound
	}

	// Get the requested enrollment token object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	cacheEntry, err := cacheClient.Get(ctx,
		fmt.Sprintf(enrollTokenPrefix, token)).Result()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheGet)
	if err != nil {
		if err == redis.Nil {
			metrics.MetricCacheGetEnrollmentTokenCacheMisses.Inc()
			return nil, ErrCacheNotFound
		}

		dstsLogger.Error("Error while looking up the enrollment token in the cache!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
		metrics.MetricCacheGetEnrollmentTokenFailures.Inc()
		return nil, err
	}

	metrics.MetricCacheGetEnrollmentTokenCacheHits.Inc()
	return []byte(cacheEntry), nil
}

// RemoveEnrollmentToken - remove the cached enrollment token for the specified
// tenant. This function is typically called from within a goroutine and errors
// removing from the cache are not surfaced to the caller.
func RemoveEnrollmentToken(requestID string, tenantID string) {
	if !isEnabled {
		return
	}

	// Delete the requested device object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err := cacheClient.Del(ctx, fmt.Sprintf(enrollTokenPrefix, tenantID)).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheDel)
	if err != nil {
		dstsLogger.Error("Failed to remove the enrollment token from the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Tenant ID: ", tenantID),
			zap.Error(err),
		)
		metrics.MetricCacheDelEnrollmentTokenFailures.Inc()
	}
}
