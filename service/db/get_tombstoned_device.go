// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func GetTombstonedDevice(requestID string, tenantID string,
	deviceID string) (*TombstonedDevice, error) {
	var foundDevice TombstonedDevice
	start := time.Now()

	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbGetTombstonedDevice)

	response := gDbPool.QueryRow(ctx, queryTombstonedDeviceByID, deviceID, tenantID)
	err := response.Scan(&foundDevice.DeviceId, &foundDevice.TenantId,
		&foundDevice.TombstonedAt)
	if err != nil {
		dstsLogger.Error("Failed to find the specified tombstoned device in the database!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", deviceID),
			zap.String("Tenant ID", tenantID),
			zap.Error(err),
		)

		if errors.Is(err, pgx.ErrNoRows) {
			metrics.MetricDatabaseTombstonedDeviceNotFoundErrors.Inc()
			return nil, ErrNotFound
		}

		err = mapContextTimeoutError(err)
		metrics.MetricDatabaseGetTombstonedDeviceFailures.Inc()
		return nil, err
	}

	dstsLogger.Debug("Found tombstoned device within the requested tenant",
		zap.String("Request ID", requestID),
		zap.String("Device ID", deviceID),
		zap.String("Tenant ID", tenantID),
	)
	return &foundDevice, nil
}
