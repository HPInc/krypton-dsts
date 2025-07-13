// package github.com/HPInc/krypton-dsts/service/cache
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// AddDeviceAuthenticationChallenge - Add the specified challenge code to the
// cache. The challenge code is later retrieved when completing the device
// authentication process.
func AddDeviceAuthenticationChallenge(requestID string, deviceID string,
	challenge string) (time.Time, error) {
	if !isEnabled {
		return time.Now(), nil
	}

	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	err := cacheClient.Set(ctx,
		fmt.Sprintf(challengePrefix, deviceID), challenge,
		ttlDeviceAuthenticationChallenge).Err()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheSet)
	if err != nil {
		// Other errors setting the challenge entry in the cache.
		dstsLogger.Error("Failed to cache device authentication challenge.",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		metrics.MetricCacheSetChallengeFailures.Inc()
		return time.Now(), err
	}

	return time.Now().Add(ttlDeviceAuthenticationChallenge), nil
}

// GetDeviceAuthenticationChallenge - Retrieve the specified challenge code from
// the cache. This is used when completing the device authentication process and
// verifying that the signed assertion presented by the client has a valid
// challenge code.
func GetDeviceAuthenticationChallenge(requestID, deviceID string) (string,
	error) {
	if !isEnabled {
		return "", nil
	}

	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	start := time.Now()
	challenge, err := cacheClient.Get(ctx,
		fmt.Sprintf(challengePrefix, deviceID)).Result()
	metrics.ReportLatencyMetric(metrics.MetricCacheLatency, start,
		operationCacheGet)
	if err != nil {
		// Cache miss - we couldn't find the requested challenge code
		// in the cache. The TTL may have expired for the entry or an
		// invalid challenge code may have been presented.
		if err == redis.Nil {
			metrics.MetricCacheGetChallengeCacheMisses.Inc()
			return "", ErrCacheNotFound
		}

		// Other errors getting the challenge entry from the cache.
		dstsLogger.Error("Failed to retrieve device authentication challenge from cache!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", deviceID),
			zap.Error(err),
		)
		metrics.MetricCacheGetChallengeFailures.Inc()
		return "", err
	}

	metrics.MetricCacheGetChallengeCacheHits.Inc()
	return challenge, nil
}
