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

// DeletePreviousCertificateThumbprint - Removes the previous certificate thumbprint from
// the specified device object in the database. This function is invoked after a successful
// device certificate rollover. After this operation, the previous device certificate can
// no longer be used for device authentication.
func DeletePreviousCertificateThumbprint(requestID string, deviceID string,
	tenantID string) error {
	start := time.Now()

	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer func() {
		cancelFunc()
		metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbUpdateDevice)
	}()

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to update device!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
			zap.Error(err),
		)
		return err
	}

	ct, err := tx.Exec(ctx, queryDeletePreviousCertThumbprint, deviceID, tenantID)
	if err != nil {
		rollback(tx, ctx)

		dstsLogger.Error("Failed to delete the previous cert thumbprint requested device from the database!",
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

		metrics.MetricDatabaseUpdateDeviceFailures.Inc()
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

		// Remove the cache entry. The next subsequent read of this device
		// will refresh the cache entry.
		cache.RemoveDevice(requestID, deviceID)

		metrics.MetricDatabaseDevicesUpdated.Inc()
		dstsLogger.Info("Removed the previous certificate for device in the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
		)
	}
	return err
}
