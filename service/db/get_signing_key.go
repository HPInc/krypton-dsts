// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func (s *SigningKey) GetSigningKey(keyID string) (*SigningKey, error) {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbGetSigningKey)

	response := gDbPool.QueryRow(ctx, queryGetSigningKey, keyID)
	err := response.Scan(&s.KeyId, &s.PrivateKey,
		&s.IsEnabled, &s.IsPrimary)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("Signing key was not found!",
				zap.String("Key ID", keyID),
			)
			return nil, ErrNotFound
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Error finding the signing key in the database!",
			zap.String("Key ID", keyID),
			zap.Error(err),
		)
		return nil, err
	}

	dstsLogger.Info("Found signing key in the database",
		zap.String("Key ID", keyID),
	)
	return s, nil
}

// Retrieve the signing key marked as primary in the database.
func (s *SigningKey) GetPrimarySigningKey() (*rsa.PrivateKey, error) {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbGetSigningKey)

	response := gDbPool.QueryRow(ctx, queryGetPrimarySigningKey)
	err := response.Scan(&s.KeyId, &s.PrivateKey,
		&s.IsEnabled, &s.IsPrimary)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("Primary signing key was not found!",
				zap.String("Key ID", s.KeyId),
			)
			return nil, ErrNotFound
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Error finding the primary signing key in the database!",
			zap.String("Key ID", s.KeyId),
			zap.Error(err),
		)
		return nil, err
	}

	// PEM decode the private key and return it.
	key, err := decodePrivateKey(s.PrivateKey)
	if err != nil {
		dstsLogger.Error("Failed to decode the primary signing key!",
			zap.String("Key ID", s.KeyId),
			zap.Error(err),
		)
		return nil, err
	}

	dstsLogger.Debug("Found primary signing key in the database",
		zap.String("Key ID", s.KeyId),
	)
	return key, nil
}
