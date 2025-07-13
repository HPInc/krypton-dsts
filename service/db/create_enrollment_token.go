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

// Create an enrollment token within the specified tenant.
func (e *EnrollmentToken) CreateEnrollmentToken(requestID string) error {

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbCreateEnrollmentToken)

	tx, err := acquire(ctx)
	if err != nil {
		dstsLogger.Error("Failed to acquire transaction to create signing key!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", e.TenantId),
			zap.Error(err),
		)
		return err
	}

	response := tx.QueryRow(ctx, queryInsertNewEnrollmentToken, e.TenantId, e.Token,
		e.TokenExpiresAt)
	err = response.Scan(&e.TenantId, &e.TokenExpiresAt, &e.CreatedAt)
	if err != nil {
		rollback(tx, ctx)
		metrics.MetricDatabaseCreateEnrollmentTokenFailures.Inc()
		if isDuplicateKeyError(err) {
			dstsLogger.Error("Duplicate enrollment token already exists in the database!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", e.TenantId),
			)
			return ErrDuplicateEntry
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Failed to create an enrollment token in the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", e.TenantId),
			zap.Error(err),
		)
		return err
	}

	err = commit(tx, ctx)
	if err == nil {
		metrics.MetricDatabaseEnrollmentTokensCreated.Inc()
		dstsLogger.Info("Successfully created an enrollment token in the database!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", e.TenantId),
		)

		// Add the enrollment token to the cache on a separate goroutine.
		go cache.AddEnrollmentToken(requestID, e.TenantId, e)
	}
	return err
}
