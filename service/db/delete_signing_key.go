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

// Delete the requested signing key from the database.
func (s *SigningKey) DeleteSigningKey(keyID string) error {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbDeleteSigningKey)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to delete signing key!",
			zap.String("Signing key ID", keyID),
			zap.Error(err),
		)
		return err
	}

	ct, err := tx.Exec(ctx, queryDeleteSigningKey, keyID)
	if err != nil {
		rollback(tx, ctx)

		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("No matching signing key was found in the database!",
				zap.String("Key ID:", keyID),
			)
			return ErrNotFound
		}

		dstsLogger.Error("Failed to delete the requested signing key from the database!",
			zap.String("Key ID:", keyID),
		)
		return ErrInternalError
	}

	err = commit(tx, ctx)
	if err == nil {
		if ct.RowsAffected() == 0 {
			dstsLogger.Error("No matching signing key was found in the database!",
				zap.String("Key ID:", keyID),
			)
			return ErrNotFound
		}

		dstsLogger.Info("Deleted the requested signing key from the database!",
			zap.String("Key ID:", keyID),
		)
	}
	return err
}
