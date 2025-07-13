// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// Delete the requested registered app from the database.
func (a *RegisteredApp) DeleteRegisteredApp(requestID string, appID string) error {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbDeleteRegisteredApp)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to delete registered app!",
			zap.String("Request ID", requestID),
			zap.String("App ID", appID),
			zap.Error(err),
		)
		return err
	}

	ct, err := tx.Exec(ctx, queryDeleteRegisteredApp, appID)
	if err != nil {
		rollback(tx, ctx)

		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("No matching registered app was found in the database!",
				zap.String("Request ID", requestID),
				zap.String("App ID", appID),
			)
			return ErrNotFound
		}

		dstsLogger.Error("Failed to delete the requested registered app from the database!",
			zap.String("Request ID", requestID),
			zap.String("App ID", appID),
			zap.Error(err),
		)
		return ErrInternalError
	}

	err = commit(tx, ctx)
	if err == nil {
		if ct.RowsAffected() == 0 {
			dstsLogger.Error("No matching registered app was found in the database!",
				zap.String("App ID: ", appID),
			)
			return ErrNotFound
		}

		// Remove the app from the cache on a separate goroutine.
		go cache.RemoveRegisteredApp(requestID, appID)

		dstsLogger.Info("Deleted the requested registered app from the database!",
			zap.String("App ID: ", appID),
		)
	}
	return err
}
