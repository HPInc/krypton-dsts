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
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

const (
	UpdateFieldIsEnabled             = "IsEnabled"
	UpdateFieldIsLost                = "IsLost"
	UpdateFieldCertificateThumbprint = "CertificateThumbprint"
	UpdateFieldCertificateIssuedAt   = "CertificateIssuedAt"
	UpdateFieldCertificateExpiresAt  = "CertificateExpiresAt"
)

// Update information about the specified device in the specified tenant.
func UpdateDevice(requestID string, deviceID string, tenantID string,
	updateMap map[string]interface{}) error {
	start := time.Now()
	batch := &pgx.Batch{}

	// Process update requests for the isEnabled field.
	val, ok := updateMap[UpdateFieldIsEnabled]
	if ok {
		isEnabled, ok := val.(bool)
		if !ok {
			dstsLogger.Error("Invalid value specified for the IsEnabled field!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}
		batch.Queue(queryUpdateDeviceIsEnabled, deviceID, tenantID, isEnabled)
	}

	// Process update requests for the isLost field.
	val, ok = updateMap[UpdateFieldIsLost]
	if ok {
		isLost, ok := val.(bool)
		if !ok {
			dstsLogger.Error("Invalid value specified for the isLost field!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}
		batch.Queue(queryUpdateDeviceIsLost, deviceID, tenantID, isLost)
	}

	// Process update requests for the certificate thumbprint and its timestamps
	val, ok = updateMap[UpdateFieldCertificateThumbprint]
	if ok {
		certThumprint, ok := val.(string)
		if !ok {
			dstsLogger.Error("Invalid value specified for the certificate thumbprint field!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}

		// Process the certificate issued at field. If it was not specified, reject
		// the request.
		val, ok = updateMap[UpdateFieldCertificateIssuedAt]
		if !ok {
			dstsLogger.Error("Certificate issued at field was not specified!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}
		issuedAt, ok := val.(time.Time)
		if !ok {
			dstsLogger.Error("Invalid value specified for the certificate issued at field!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}

		// Process the certificate expires at field. If it was not specified, reject
		// the request.
		val, ok = updateMap[UpdateFieldCertificateExpiresAt]
		if !ok {
			dstsLogger.Error("Certificate expires_at field was not specified!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}
		expiresAt, ok := val.(time.Time)
		if !ok {
			dstsLogger.Error("Invalid value specified for the certificate expires at field!")
			metrics.MetricDatabaseUpdateDeviceFailures.Inc()
			return ErrInvalidRequest
		}

		batch.Queue(queryUpdateDeviceCertificate, deviceID, tenantID, certThumprint,
			issuedAt, expiresAt)
	}

	if batch.Len() == 0 {
		dstsLogger.Error("No updates found in the update device request!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
		)
		return ErrInvalidRequest
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()

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

	// Send the batch of queries to the database for execution.
	br := tx.SendBatch(ctx, batch)
	ct, err := br.Exec()
	if err != nil {
		dstsLogger.Error("Failed to update device in the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
			zap.Error(err),
		)
		metrics.MetricDatabaseUpdateDeviceFailures.Inc()
		_ = br.Close()
		rollback(tx, ctx)
		return ErrInternalError
	}

	if ct.RowsAffected() == 0 {
		dstsLogger.Error("Device with the specified device ID was not found in the tenant!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
		)
		metrics.MetricDatabaseDeviceNotFoundErrors.Inc()
		_ = br.Close()
		rollback(tx, ctx)
		return ErrNotFound
	}

	err = br.Close()
	if err != nil {
		dstsLogger.Error("Failed to close batch result!",
			zap.Error(err),
		)
		rollback(tx, ctx)
		return ErrInternalError
	}

	err = commit(tx, ctx)
	if err == nil {
		metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbUpdateDevice)
		metrics.MetricDatabaseDevicesUpdated.Inc()

		// Remove the cache entry on a separate goroutine. The next subsequent
		// read of this device will refresh the cache entry.
		cache.RemoveDevice(requestID, deviceID)

		dstsLogger.Info("Updated device in the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.String("Device ID", deviceID),
		)
	}
	return err
}
