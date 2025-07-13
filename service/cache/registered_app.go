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

// AddRegisteredApp - cache information about the specified app. This function is
// typically called from a goroutine and errors adding to the cache are not
// surfaced to the caller.
func AddRegisteredApp(requestID string, appID string, app interface{}) {
	if !isEnabled {
		return
	}

	// Marshal the app object for caching.
	cacheEntry, err := json.Marshal(app)
	if err != nil {
		dstsLogger.Error("Failed to marshal app for caching!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		return
	}

	// Add the app to the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err = cacheClient.Set(ctx, fmt.Sprintf(appPrefix, appID),
		cacheEntry, ttlApp).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheSet)
	if err != nil {
		dstsLogger.Error("Failed to add the app to the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", appID),
			zap.Error(err),
		)
		metrics.MetricCacheSetDeviceFailures.Inc()
	}
}

// GetRegisteredApp - retrieve information about a registered app from the cache.
func GetRegisteredApp(requestID string, appID string) ([]byte, error) {
	if !isEnabled {
		return nil, ErrCacheNotFound
	}

	// Get the requested app object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	cacheEntry, err := cacheClient.Get(ctx,
		fmt.Sprintf(appPrefix, appID)).Result()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheGet)
	if err != nil {
		if err == redis.Nil {
			metrics.MetricCacheGetAppCacheMisses.Inc()
			return nil, ErrCacheNotFound
		}

		dstsLogger.Error("Error while looking up the app in the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		metrics.MetricCacheGetDeviceFailures.Inc()
		return nil, err
	}

	metrics.MetricCacheGetAppCacheHits.Inc()
	return []byte(cacheEntry), nil
}

// RemoveDevice - remove cached information about the specified app. This
// function is typically called from within a goroutine and errors removing
// from the cache are not surfaced to the caller.
func RemoveRegisteredApp(requestID string, appID string) {
	if !isEnabled {
		return
	}

	// Delete the requested app object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err := cacheClient.Del(ctx, fmt.Sprintf(appPrefix, appID)).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheDel)
	if err != nil {
		dstsLogger.Error("Failed to remove the registered app from the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("App ID: ", appID),
			zap.Error(err),
		)
		metrics.MetricCacheDelAppFailures.Inc()
	}
}
