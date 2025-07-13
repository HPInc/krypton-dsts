// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// GetRegisteredApp - retrieve information about a registered app from the database.
func GetRegisteredApp(requestID string, appID string) (*RegisteredApp,
	error) {
	var foundApp RegisteredApp

	cacheEntry, err := cache.GetRegisteredApp(requestID, appID)
	if err == nil {
		err = json.Unmarshal([]byte(cacheEntry), &foundApp)
		if err != nil {
			dstsLogger.Error("Failed to unmarshal app from cache",
				zap.String("Request ID", requestID),
				zap.String("App ID", appID),
			)
		}
	}

	// App was not found in the cache. Check to see if it is available in
	// the database.
	if err != nil {
		start := time.Now()
		ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
		defer cancelFunc()
		defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbGetRegisteredApp)

		response := gDbPool.QueryRow(ctx, queryGetRegisteredApp, appID)
		err = response.Scan(&foundApp.AppId, &foundApp.Name, &foundApp.IsEnabled,
			&foundApp.PublicKeyBytes, &foundApp.CreatedAt, &foundApp.UpdatedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				dstsLogger.Error("Registered app was not found!",
					zap.String("Request ID", requestID),
					zap.String("App ID", appID),
				)
				return nil, ErrNotFound
			}

			err = mapContextTimeoutError(err)
			dstsLogger.Error("Error finding the registered app in the database!",
				zap.String("Request ID", requestID),
				zap.String("App ID", appID),
				zap.Error(err),
			)
			return nil, err
		}

		dstsLogger.Debug("Found registered app in the database",
			zap.String("Request ID", requestID),
			zap.String("App ID", appID),
		)

		// Add the app to the cache on a separate goroutine.
		go cache.AddRegisteredApp(requestID, foundApp.AppId, foundApp)
	}

	foundApp.PublicKey, err = decodePublicKey(foundApp.PublicKeyBytes)
	if err != nil {
		dstsLogger.Error("Failed to decode the public key for the app!",
			zap.String("Request ID", requestID),
			zap.String("App ID", appID),
			zap.Error(err),
		)
		return nil, err
	}

	return &foundApp, nil
}
