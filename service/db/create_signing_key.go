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

// NewSigningKey - creates a signing key record for storing in the database. The
// specified RSA private key is PEM encoded in memory and added to the signing
// key record.
func NewSigningKey(keyID string, privateKey *rsa.PrivateKey,
	isPrimary bool) (*SigningKey, error) {
	var err error

	if privateKey == nil || keyID == "" {
		return nil, ErrInvalidRequest
	}

	newKey := SigningKey{
		KeyId:     keyID,
		IsEnabled: true,
	}
	if isPrimary {
		newKey.IsPrimary = true
	}

	// PEM encode the private key to store it in the signing key table.
	newKey.PrivateKey, err = encodePrivateKey(privateKey)
	if err != nil {
		dstsLogger.Error("Failed to encode private key to memory!",
			zap.Error(err),
		)
		return nil, err
	}

	return &newKey, nil
}

// Add the requested signing key to the database.
func (s *SigningKey) AddSigningKey() error {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbAddSigningKey)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to create signing key!",
			zap.String("Key ID", s.KeyId),
			zap.Error(err),
		)
		return err
	}

	err = tx.QueryRow(ctx, queryInsertNewSigningKey, s.KeyId, s.PrivateKey,
		s.IsEnabled, s.IsPrimary).
		Scan(&s.KeyId, &s.IsEnabled, &s.IsPrimary)
	if err != nil {
		rollback(tx, ctx)
		if isDuplicateKeyError(err) {
			dstsLogger.Error("Key with the same signing key ID already exists in the database!",
				zap.String("Key ID", s.KeyId),
			)
			return ErrDuplicateEntry
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Failed to add the signing key to the database!",
			zap.String("Key ID", s.KeyId),
			zap.Error(err),
		)
		return err
	}

	err = commit(tx, ctx)
	if err == nil {
		dstsLogger.Info("Successfully created a signing key in the database!",
			zap.String("Key ID", s.KeyId),
		)
	}
	return err
}
