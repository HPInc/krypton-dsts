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

func GetEnrollmentTokenForTenant(requestID string, tenantID string) (*EnrollmentToken,
	error) {
	var token EnrollmentToken

	start := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFunc()
	defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
		operationDbGetEnrollmentToken)

	response := gDbPool.QueryRow(ctx, queryGetEnrollmentToken, tenantID)
	err := response.Scan(&token.TenantId, &token.Token, &token.TokenExpiresAt,
		&token.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			dstsLogger.Error("Enrollment token for the specified tenant was not found!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", tenantID),
			)
			metrics.MetricDatabaseEnrollmentTokenNotFoundErrors.Inc()
			return nil, ErrNotFound
		}

		err = mapContextTimeoutError(err)
		dstsLogger.Error("Failed to find the enrollment token in the specified tenant!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", tenantID),
			zap.Error(err),
		)
		metrics.MetricDatabaseGetEnrollmentTokenFailures.Inc()
		return nil, err
	}

	metrics.MetricDatabaseEnrollmentTokensRetrieved.Inc()
	dstsLogger.Info("Found enrollment token within the requested tenant",
		zap.String("Request ID", requestID),
		zap.String("Tenant ID", tenantID),
	)
	return &token, nil
}

func GetEnrollmentTokenInfo(requestID string, enrollmentToken string) (*EnrollmentToken,
	error) {
	var token EnrollmentToken

	cacheEntry, err := cache.GetEnrollmentTokenInfo(requestID, enrollmentToken)
	if err == nil {
		dstsLogger.Info("GetEnrollmentTokenForTenant - cache hit!")
		err = json.Unmarshal([]byte(cacheEntry), &token)
		if err != nil {
			dstsLogger.Error("Failed to unmarshal enrollment token from cache",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", token.TenantId),
			)
		}
	}

	// Enrollment token was not found in the cache. Check to see if it is available in
	// the database.
	if err != nil {
		start := time.Now()
		ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
		defer cancelFunc()
		defer metrics.ReportLatencyMetric(metrics.MetricDatabaseLatency, start,
			operationDbGetEnrollmentToken)

		response := gDbPool.QueryRow(ctx, queryGetEnrollmentTokenInfo, enrollmentToken)
		err := response.Scan(&token.TenantId, &token.Token, &token.TokenExpiresAt,
			&token.CreatedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				dstsLogger.Error("Specified enrollment token was not found!",
					zap.String("Request ID", requestID),
					zap.String("Tenant ID", token.TenantId),
				)
				metrics.MetricDatabaseEnrollmentTokenNotFoundErrors.Inc()
				return nil, ErrNotFound
			}

			err = mapContextTimeoutError(err)
			dstsLogger.Error("Error finding the enrollment token in the database!",
				zap.String("Request ID", requestID),
				zap.String("Tenant ID", token.TenantId),
				zap.Error(err),
			)
			metrics.MetricDatabaseGetEnrollmentTokenFailures.Inc()
			return nil, err
		}

		metrics.MetricDatabaseEnrollmentTokensRetrieved.Inc()
	}

	dstsLogger.Debug("Found enrollment token information!",
		zap.String("Request ID", requestID),
		zap.String("Tenant ID", token.TenantId),
	)
	return &token, nil
}
