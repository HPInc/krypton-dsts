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

// AddDevice - cache information about the specified device. This function is
// typically called from a goroutine and errors adding to the cache are not
// surfaced to the caller.
func AddDevice(requestID string, deviceID string, device interface{}) {
	if !isEnabled {
		return
	}

	// Marshal the device object for caching.
	cacheEntry, err := json.Marshal(device)
	if err != nil {
		dstsLogger.Error("Failed to marshal device for caching!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		return
	}

	// Add the device to the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err = cacheClient.Set(ctx, fmt.Sprintf(devicePrefix, deviceID),
		cacheEntry, ttlDevice).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheSet)
	if err != nil {
		dstsLogger.Error("Failed to add the device to the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		metrics.MetricCacheSetDeviceFailures.Inc()
	}
}

// GetDevice - retrieve information about a device object from the cache.
func GetDevice(requestID string, deviceID string) ([]byte, error) {
	if !isEnabled {
		return nil, ErrCacheNotFound
	}

	// Get the requested device object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	cacheEntry, err := cacheClient.Get(ctx,
		fmt.Sprintf(devicePrefix, deviceID)).Result()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheGet)
	if err != nil {
		if err == redis.Nil {
			metrics.MetricCacheGetDeviceCacheMisses.Inc()
			return nil, ErrCacheNotFound
		}

		dstsLogger.Error("Error while looking up the device in the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		metrics.MetricCacheGetDeviceFailures.Inc()
		return nil, err
	}

	metrics.MetricCacheGetDeviceCacheHits.Inc()
	return []byte(cacheEntry), nil
}

// RemoveDevice - remove cached information about the specified device. This
// function is typically called from within a goroutine and errors removing
// from the cache are not surfaced to the caller.
func RemoveDevice(requestID string, deviceID string) {
	if !isEnabled {
		return
	}

	// Delete the requested device object from the cache.
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err := cacheClient.Del(ctx, fmt.Sprintf(devicePrefix, deviceID)).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheDel)
	if err != nil {
		dstsLogger.Error("Failed to remove the device from the cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		metrics.MetricCacheDelDeviceFailures.Inc()
	}
}
