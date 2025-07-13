// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func trimQuotes(str string) string {
	s := strings.TrimSpace(str)

	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func (d *Device) ListDevicesPaginated(requestID string, tenantID string,
	filter string, page *Paginator) ([]Device, error) {
	var (
		err      error
		start    time.Time
		response pgx.Rows
	)

	devices := []Device{}

	start = time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()

	if filter != "" {
		// A filter was specified in the request. Parse the specified filter
		// and figure out what is being requested.
		queries := strings.Split(filter, "=")
		if len(queries) != 2 {
			dstsLogger.Error("Invalid filter format requested.",
				zap.String("Filter requested: ", filter),
			)
			return nil, errors.New("invalid filter format requested")
		}

		switch strings.TrimSpace(queries[0]) {
		case "enabled":
			// List all devices in the tenant filtered by their current isEnabled
			// state.
			// filter: enabled=true or enabled=false
			stateRequested := trimQuotes(queries[1])
			if stateRequested != "true" && stateRequested != "false" {
				dstsLogger.Error("Invalid value for enabled filter requested.",
					zap.String("Filter requested: ", filter),
				)
				return nil, errors.New("invalid filter value requested")
			}

			// Look for all devices in the tenant that match the requested isEnabled
			// state.
			response, err = gDbPool.Query(ctx, queryListEnabledDevicesInTenant, tenantID)

		default:
			dstsLogger.Error("Unsupported filter requested",
				zap.String("Filter requested: ", filter),
			)
			return nil, errors.New("invalid filter format requested")
		}
	} else {
		// No filter was specified in the request. List all devices belonging to
		// the specified tenant.
		response, err = gDbPool.Query(ctx, queryListAllDevicesInTenant, tenantID)
	}

	if err != nil {
		dstsLogger.Error("Failed to get a list of devices for the specified tenant!",
			zap.Error(err),
		)
		return nil, err
	}
	defer response.Close()

	for response.Next() {
		var foundDevice Device
		err = response.Scan(&foundDevice.DeviceId, &foundDevice.TenantId,
			&foundDevice.IsEnabled, &foundDevice.IsLost, &foundDevice.CertificateThumbprint,
			&foundDevice.CertificateIssuedAt, &foundDevice.CertificateExpiresAt,
			&foundDevice.CreatedAt, &foundDevice.UpdatedAt, &foundDevice.ServiceId,
			&foundDevice.HardwareHash)
		if err != nil {
			dstsLogger.Error("Failed to get a list of devices from the database!",
				zap.String("Request ID: ", requestID),
				zap.String("Tenant ID: ", tenantID),
				zap.Error(err),
			)
			return nil, err
		}
		devices = append(devices, foundDevice)
	}

	if response.Err() != nil {
		dstsLogger.Error("Failed to retreive list of devices for the specified tenant!",
			zap.String("Request ID: ", requestID),
			zap.String("Tenant ID: ", tenantID),
			zap.String("Filter: ", filter),
		)
		metrics.MetricDatabaseListDevicesFailures.Inc()
		return nil, err
	}

	metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbListDevices)
	metrics.MetricDatabaseDevicesRetrieved.Add(float64(len(devices)))

	dstsLogger.Info("Retrieved devices for the specified tenant!",
		zap.String("Request ID: ", requestID),
		zap.String("Tenant ID: ", tenantID),
		zap.String("Filter: ", filter),
		zap.Int("Number of records: ", len(devices)),
	)
	return devices, nil
}
