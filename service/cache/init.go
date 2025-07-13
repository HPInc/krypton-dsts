// package github.com/HPInc/krypton-dsts/service/cache
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	// Structured logging using Uber Zap.
	dstsLogger *zap.Logger

	cacheClient *redis.Client
	isEnabled   bool
	gCtx        context.Context

	ErrCacheNotFound = errors.New("item not found in cache")
)

const (
	// Cache connection string.
	cacheConnStr = "%s:%d"

	// Timeout for requests to the Redis cache.
	cacheTimeout = (time.Second * 1)
	dialTimeout  = (time.Second * 5)
	readTimeout  = (time.Second * 3)
	writeTimeout = (time.Second * 3)
	poolSize     = 10
	poolTimeout  = (time.Second * 4)

	// Cache key prefix strings.
	challengePrefix   = "challenge:%s"
	appPrefix         = "app:%s"
	devicePrefix      = "device:%s"
	enrollTokenPrefix = "enroll_token:%s" // #nosec G101

	// TTLs for cache entries.
	ttlDeviceAuthenticationChallenge = (time.Minute * 1)
	ttlDevice                        = (time.Hour * 2)
	ttlApp                           = (time.Hour * 6)

	// Caching operation names.
	operationCacheSet = "set"
	operationCacheGet = "get"
	operationCacheDel = "del"
)

// Init - initialize a connection to the Redis based device cache.
func Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) error {
	cacheConfig := cfgMgr.GetCacheConfig()
	dstsLogger = logger
	isEnabled = cacheConfig.Enabled

	if !isEnabled {
		dstsLogger.Info("Caching is disabled - nothing to initialize!")
		return nil
	}

	// Initialize the cache client with appropriate connection options.
	cacheClient = redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf(cacheConnStr, cacheConfig.Host, cacheConfig.Port),
		Password:     cacheConfig.Password,
		DB:           cacheConfig.CacheDatabase,
		DialTimeout:  dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		PoolSize:     poolSize,
		PoolTimeout:  poolTimeout,
	})

	// Attempt to connect to the device cache.
	gCtx = context.Background()
	ctx, cancelFunc := context.WithTimeout(gCtx, cacheTimeout)
	defer cancelFunc()

	_, err := cacheClient.Ping(ctx).Result()
	if err != nil {
		dstsLogger.Error("Failed to connect to the device cache!",
			zap.String("Cache address: ", cacheClient.Options().Addr),
			zap.Error(err),
		)
		return err
	}

	dstsLogger.Info("Successfully initialized the device cache!",
		zap.String("Cache address: ", cacheClient.Options().Addr),
	)
	return nil
}

// Shutdown the device cache and cleanup Redis connections.
func Shutdown() {
	if !isEnabled {
		dstsLogger.Info("Device cache was not initialized - skipping shutdown!")
		return
	}

	gCtx.Done()
	isEnabled = false

	// Close the client connection to the cache.
	err := cacheClient.Close()
	if err != nil {
		dstsLogger.Error("Failed to shutdown connection to the device cache!",
			zap.Error(err),
		)
		return
	}

	dstsLogger.Info("Successfully shutdown connection to the device cache!")
}
