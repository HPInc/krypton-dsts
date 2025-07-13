// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
)

func NewRegisteredApp(appID string, appName string, isEnabled bool,
	publicKey *rsa.PublicKey) (*RegisteredApp, error) {
	var err error

	if publicKey == nil || appID == "" {
		return nil, ErrInvalidRequest
	}

	newApp := RegisteredApp{
		AppId:     appID,
		Name:      appName,
		IsEnabled: isEnabled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// PEM encode the public key to store it in the registered apps table.
	newApp.PublicKeyBytes, err = encodePublicKey(publicKey)
	if err != nil {
		dstsLogger.Error("Failed to encode the public key to memory!",
			zap.Error(err),
		)
		return nil, err
	}

	return &newApp, nil
}

// Add the requested app registration to the database.
func (a *RegisteredApp) AddOrUpdateRegisteredApp() error {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbAddRegisteredApp)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to create registered app!",
			zap.String("App ID", a.AppId),
			zap.Error(err),
		)
		return err
	}

	response := tx.QueryRow(ctx, queryInsertNewRegisteredApp, a.AppId, a.Name,
		a.IsEnabled, a.PublicKeyBytes)
	err = response.Scan(&a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		rollback(tx, ctx)
		metrics.MetricDatabaseCreateDeviceFailures.Inc()
		if isDuplicateKeyError(err) {
			dstsLogger.Error("Duplicate registered app exists in the database!",
				zap.String("App ID", a.AppId),
				zap.Error(err),
			)
			return ErrDuplicateEntry
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Failed to add the registered app to the database!",
			zap.String("App ID", a.AppId),
			zap.Error(err),
		)
		return err
	}

	err = commit(tx, ctx)
	if err == nil {
		dstsLogger.Info("Registered app was updated in the database!",
			zap.String("App ID:", a.AppId),
		)
	}
	return err
}
