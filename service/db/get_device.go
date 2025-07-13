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

// Get information about a device with the specified device ID within the
// specified tenant.
func GetDevice(requestID string, tenantID string,
	deviceID string) (*Device, error) {
	var foundDevice Device

	cacheEntry, err := cache.GetDevice(requestID, deviceID)
	if err == nil {
		err = json.Unmarshal([]byte(cacheEntry), &foundDevice)
		if err != nil {
			dstsLogger.Error("Failed to unmarshal device from cache",
				zap.String("Request ID", requestID),
				zap.String("Device ID", deviceID),
				zap.String("Tenant ID", tenantID),
			)
		}
	}

	// Device was not found in the cache. Check to see if it is available in
	// the database.
	if err != nil {
		start := time.Now()

		ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
		defer cancelFunc()
		defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbGetDevice)

		response := gDbPool.QueryRow(ctx, queryDeviceByID, deviceID, tenantID)
		err = response.Scan(&foundDevice.DeviceId, &foundDevice.TenantId,
			&foundDevice.IsEnabled, &foundDevice.IsLost, &foundDevice.CertificateThumbprint,
			&foundDevice.CertificateIssuedAt, &foundDevice.CertificateExpiresAt,
			&foundDevice.PreviousCertificateThumbprint, &foundDevice.CreatedAt, &foundDevice.UpdatedAt,
			&foundDevice.ServiceId, &foundDevice.HardwareHash)
		if err != nil {
			dstsLogger.Error("Failed to find the specified device in the database!",
				zap.String("Request ID", requestID),
				zap.String("Device ID", deviceID),
				zap.String("Tenant ID", tenantID),
				zap.Error(err),
			)

			if errors.Is(err, pgx.ErrNoRows) {
				metrics.MetricDatabaseDeviceNotFoundErrors.Inc()

				// Check if the device exists in the tombstoned devices table.
				_, err = GetTombstonedDevice(requestID, tenantID, deviceID)
				if err == nil {
					return nil, ErrTombstoned
				}
				return nil, ErrNotFound
			}

			err = mapContextTimeoutError(err)
			metrics.MetricDatabaseGetDeviceFailures.Inc()
			return nil, err
		}

		metrics.MetricDatabaseDevicesRetrieved.Inc()
		// Add the device to the cache on a separate goroutine.
		go cache.AddDevice(requestID, foundDevice.DeviceId, foundDevice)
	}

	dstsLogger.Debug("Found device within the requested tenant",
		zap.String("Request ID", requestID),
		zap.String("Device ID", deviceID),
		zap.String("Tenant ID", tenantID),
	)
	return &foundDevice, nil
}
