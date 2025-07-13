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

// Delete the requested enrollment token from the database.
func (e *EnrollmentToken) DeleteEnrollmentToken(requestID string,
	tenantID string) error {
	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbDeleteEnrollmentToken)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to delete enrollment token!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.Error(err),
		)
		return err
	}

	ct, err := tx.Exec(ctx, queryDeleteEnrollmentToken, tenantID)
	if err != nil {
		rollback(tx, ctx)

		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("No matching enrollment token was found in the database!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", tenantID),
			)
			metrics.MetricDatabaseEnrollmentTokenNotFoundErrors.Inc()
			return ErrNotFound
		}

		dstsLogger.Error("Failed to delete the requested enrollment token from the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.Error(err),
		)
		metrics.MetricDatabaseDeleteEnrollmentTokenFailures.Inc()
		return ErrInternalError
	}

	err = commit(tx, ctx)
	if err == nil {
		if ct.RowsAffected() == 0 {
			dstsLogger.Error("No matching enrollment token was found in the database!",
				zap.String("Request ID:", requestID),
				zap.String("Tenant ID: ", tenantID),
			)
			metrics.MetricDatabaseEnrollmentTokenNotFoundErrors.Inc()
			return ErrNotFound
		}

		// Remove the enrollment token from the cache on a separate goroutine.
		go cache.RemoveEnrollmentToken(requestID, tenantID)

		metrics.MetricDatabaseEnrollmentTokensDeleted.Inc()
		dstsLogger.Info("Deleted the requested enrollment token from the database!",
			zap.String("Request ID: ", requestID),
			zap.String("Tenant ID: ", tenantID),
		)
	}
	return err
}
