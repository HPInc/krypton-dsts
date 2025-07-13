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

// Delete the requested device from the database.
func DeleteDevice(requestID string, tenantID string,
	deviceID string) error {

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer func() {
		cancelFunc()
		metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbDeleteDevice)
	}()

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to delete device!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
			zap.Error(err),
		)
		return err
	}

	ct, err := tx.Exec(ctx, queryDeleteDeviceByID, deviceID, tenantID)
	if err != nil {
		rollback(tx, ctx)

		dstsLogger.Error("Failed to delete the requested device from the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
			zap.Error(err),
		)
		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("No matching device was found in the database!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", tenantID),
				zap.String("Device ID", deviceID),
			)
			metrics.MetricDatabaseDeviceNotFoundErrors.Inc()
			return ErrNotFound
		}

		metrics.MetricDatabaseDeleteDeviceFailures.Inc()
		return ErrInternalError
	}

	err = commit(tx, ctx)
	if err == nil {
		if ct.RowsAffected() == 0 {
			dstsLogger.Error("No matching device was found in the database!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", tenantID),
				zap.String("Device ID", deviceID),
			)
			metrics.MetricDatabaseDeviceNotFoundErrors.Inc()
			return ErrNotFound
		}

		// Remove the device from the cache.
		cache.RemoveDevice(requestID, deviceID)

		metrics.MetricDatabaseDevicesDeleted.Inc()
		dstsLogger.Info("Deleted the requested device from the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
		)
	}

	return err
}
