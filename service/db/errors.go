// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"errors"

	"github.com/HPInc/krypton-dsts/service/metrics"

	"github.com/jackc/pgerrcode"
	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

var (
	ErrDuplicateEntry    = errors.New("a duplicate entry was found in the database")
	ErrNotFound          = errors.New("the requested entry was not found in the database")
	ErrTombstoned        = errors.New("the requested entry is tombstoned")
	ErrNotAllowed        = errors.New("the requested operation is not allowed")
	ErrInvalidRequest    = errors.New("the request contained one or more invalid parameters")
	ErrInternalError     = errors.New("an internal error occured while performing the database operation")
	ErrAuthnBlocked      = errors.New("device authentication is blocked")
	ErrMarshalPrivateKey = errors.New("failed to marshal private key")
	ErrMarshalPublicKey  = errors.New("failed to marshal public key")
	ErrDecodePrivateKey  = errors.New("failed to decode the private key")
	ErrDecodePublicKey   = errors.New("failed to decode the public key")
	ErrDatabaseBusy      = errors.New("no available database resources to process this request")
)

func isDuplicateKeyError(err error) bool {
	pgErr, ok := err.(*pgconn.PgError)
	if ok {
		if pgErr.Code == pgerrcode.UniqueViolation {
			return true
		}
	}
	return false
}

// Check if the specified error was caused due to a context deadline being
// exceeded. If so, map the error to a database busy error, so we can return
// an HTTP 429 (Server Busy) error for the client to retry later.
func mapContextTimeoutError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrDatabaseBusy
	}
	return err
}

func acquire(ctx context.Context) (pgxv5.Tx, error) {
	tx, err := gDbPool.Begin(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrDatabaseBusy
		}
	}
	return tx, err
}

func commit(tx pgxv5.Tx, ctx context.Context) error {
	err := tx.Commit(ctx)
	if err != nil {
		dstsLogger.Error("Failed to commit transaction!",
			zap.Error(err),
		)
		metrics.MetricDatabaseCommitErrors.Inc()
	}
	return err
}

func rollback(tx pgxv5.Tx, ctx context.Context) {
	err := tx.Rollback(ctx)
	if err != nil {
		dstsLogger.Error("Failed to rollback transaction!",
			zap.Error(err),
		)
		metrics.MetricDatabaseRollbackErrors.Inc()
	}
}
