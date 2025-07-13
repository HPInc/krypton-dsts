// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
)

// Create a device within the specified tenant.
func (d *Device) CreateDevice(requestID string) error {

	// Lookup the management service specified in the request for the newly
	// created device. If no management service was specified, the default
	// management service configured in the database will be used.
	svc, err := lookupManagementService(d.ServiceId)
	if err != nil {
		dstsLogger.Error("Device management service for the device was not provided",
			zap.String("Request ID", requestID),
			zap.String("Device ID", d.DeviceId),
		)
		return ErrInvalidRequest
	}
	d.ServiceId = svc.ServiceId

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbCreateDevice)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to create device object!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", d.DeviceId),
			zap.Error(err),
		)
		return err
	}

	response := tx.QueryRow(ctx, queryInsertNewDevice, d.DeviceId, d.TenantId,
		d.IsEnabled, d.IsLost, d.CertificateThumbprint, d.CertificateIssuedAt,
		d.CertificateExpiresAt, d.ServiceId, d.HardwareHash)
	err = response.Scan(&d.CreatedAt, &d.UpdatedAt, &d.ServiceId)
	if err != nil {
		rollback(tx, ctx)
		metrics.MetricDatabaseCreateDeviceFailures.Inc()
		if isDuplicateKeyError(err) {
			dstsLogger.Error("Failed to create a new device object. Duplicate exists!",
				zap.String("Request ID", requestID),
				zap.String("Device ID", d.DeviceId),
				zap.Error(err),
			)
			return ErrDuplicateEntry
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Failed to create a new device object.",
			zap.String("Request ID", requestID),
			zap.String("Device ID", d.DeviceId),
			zap.Error(err),
		)
		return err
	}

	err = commit(tx, ctx)
	if err == nil {
		metrics.MetricDatabaseDevicesCreated.Inc()
		dstsLogger.Debug("Successfully created a device object in the database!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", d.DeviceId),
		)

		// Add the device to the cache on a separate goroutine.
		go cache.AddDevice(requestID, d.DeviceId, d)
	}
	return err
}
