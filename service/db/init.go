// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

const (
	// Maximum number of connection retries using GORM.
	maxDbConnectionRetries = 3

	// Database connection retry interval
	connectionRetryInterval                = (time.Second * 5)
	dbOperationTimeout                     = (time.Second * 5)
	defaultIdleInTransactionSessionTimeout = (time.Second * 10)
	defaultStatementTimeout                = (time.Second * 10)

	// Maximum number of records to return in one query.
	maxDbQueryPageSize = 100

	// Database operations.
	operationDbCreateDevice          = "CreateDevice"
	operationDbGetDevice             = "GetDevice"
	operationDbGetTombstonedDevice   = "GetTombstonedDevice"
	operationDbDeleteDevice          = "DeleteDevice"
	operationDbUpdateDevice          = "UpdateDevice"
	operationDbListDevices           = "ListDevices"
	operationDbCreateEnrollmentToken = "CreateEnrollmentToken"
	operationDbGetEnrollmentToken    = "GetEnrollmentToken"
	operationDbDeleteEnrollmentToken = "DeleteEnrollmentToken"
	operationDbAddSigningKey         = "AddSigningKey"
	operationDbGetSigningKey         = "GetSigningKey"
	operationDbDeleteSigningKey      = "DeleteSigningKey"
	operationDbAddRegisteredApp      = "AddRegisteredApp"
	operationDbGetRegisteredApp      = "GetRegisteredApp"
	operationDbDeleteRegisteredApp   = "DeleteRegisteredApp"
)

var (
	// Structured logging using Uber Zap.
	dstsLogger *zap.Logger

	// Connection pool to the files database.
	gDbPool *pgxpool.Pool

	// Connection string for the Postgres device database.
	postgresDsn = "host=%s port=%d user=%s dbname=%s password=%s sslmode=%s"
)

// Init - initialize the DSTS database, perform database migration, initialize
// the cache and initialize any pre-registered applications with the DSTS.
func Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) error {
	dstsLogger = logger

	// Connect to the database and initialize it.
	err := loadDeviceDatabase(cfgMgr.GetDatabaseConfig())
	if err != nil {
		dstsLogger.Error("Failed to initialize the device database!",
			zap.Error(err),
		)
		return err
	}

	// Initialize the connection to the device cache.
	err = cache.Init(dstsLogger, cfgMgr)
	if err != nil {
		dstsLogger.Error("Failed to initialize the device cache!",
			zap.Error(err),
		)
		shutdownDeviceDatabase()
		return err
	}

	// Register applications specified in the configuration file.
	return initRegisteredApps(cfgMgr.GetRegisteredApps())
}

// Shutdown - close the connection to the device database. Also close the
// connection to the device cache.
func Shutdown() {
	// Shutdown the device database and close connections.
	shutdownDeviceDatabase()

	// Shutdown the device cache.
	cache.Shutdown()
}

// Shutdown the connection to the device database.
func shutdownDeviceDatabase() {
	gDbPool.Close()
}

// Initialize Pgx configuration settings to connect to the devices database.
func initPgxConfig(dbConfig *config.DatabaseConfig, connStr string) (*pgxpool.Config,
	error) {
	pgxConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, err
	}

	if dbConfig.MaxOpenConnections == 0 {
		pgxConfig.MaxConns, err = common.ToInt32(runtime.NumCPU() * 5)
		if err != nil {
			return nil, err
		}
	} else {
		pgxConfig.MaxConns, err = common.ToInt32(dbConfig.MaxOpenConnections)
		if err != nil {
			return nil, err
		}
	}

	runtimeParams := pgxConfig.ConnConfig.RuntimeParams
	runtimeParams["application_name"] = config.ServiceName
	runtimeParams["idle_in_transaction_session_timeout"] =
		strconv.Itoa(int(defaultIdleInTransactionSessionTimeout.Milliseconds()))
	runtimeParams["statement_timeout"] =
		strconv.Itoa(int(defaultStatementTimeout.Milliseconds()))

	return pgxConfig, nil
}

func loadDeviceDatabase(dbConfig *config.DatabaseConfig) error {
	var (
		err           error
		dbInitialized = false
		connStr       string
		tlsConfig     *tls.Config
	)

	// Configure the connection to the device database.
	connStr = fmt.Sprintf(postgresDsn, dbConfig.Host, dbConfig.Port,
		dbConfig.Username, dbConfig.DatabaseName, dbConfig.Password,
		dbConfig.SslMode)

	// Load the root CA certificates and initialize TLS configuration.
	if dbConfig.SslMode != "disable" {
		certs, err := loadTlsCert(dbConfig.SslRootCertificate)
		if err != nil {
			dstsLogger.Error("Failed to load the root CA certificate for SSL connections to the database!",
				zap.String("SSL Root CA path", dbConfig.SslRootCertificate),
				zap.Error(err),
			)
			return err
		}

		tlsConfig = &tls.Config{
			RootCAs:    certs,
			ServerName: dbConfig.Host,
			MinVersion: tls.VersionTLS12,
		}
	}

	pgxConfig, err := initPgxConfig(dbConfig, connStr)
	if err != nil {
		dstsLogger.Error("Failed to initialize database connection configuration!",
			zap.String("Database host: ", dbConfig.Host),
			zap.Error(err),
		)
		return err
	}
	pgxConfig.ConnConfig.TLSConfig = tlsConfig

	// Give ourselves a few retry attempts to connect to the device database.
	for i := maxDbConnectionRetries; i > 0; i-- {
		ctx, cancelFunc := context.WithTimeout(context.Background(), dbOperationTimeout)
		gDbPool, err = pgxpool.NewWithConfig(ctx, pgxConfig)
		if err != nil {
			cancelFunc()
			dstsLogger.Error("Failed to connect to the devices database!",
				zap.String("Database host: ", dbConfig.Host),
				zap.Error(err),
			)
			time.Sleep(connectionRetryInterval)
		} else {
			// Pool creation was successful. Ping the database to ensure connectivity.
			err = gDbPool.Ping(ctx)
			cancelFunc()
			if err != nil {
				dstsLogger.Error("Failed to ping the devices database!",
					zap.String("Database host: ", dbConfig.Host),
					zap.Error(err),
				)
				gDbPool.Close()
				time.Sleep(connectionRetryInterval)
			} else {
				dbInitialized = true
				break
			}
		}
	}

	if !dbInitialized {
		dstsLogger.Error("All retry attempts to load devices database exhausted. Giving up!",
			zap.Error(err),
		)
		return err
	}

	// Perform database schema migrations.
	err = migrateDatabaseSchema(dbConfig)
	if err != nil {
		dstsLogger.Error("Failed to migrate database schema for device database!",
			zap.String("Database host: ", dbConfig.Host),
			zap.Error(err),
		)
		shutdownDeviceDatabase()
		return err
	}

	// Retrieve the list of registered management services.
	err = getRegisteredManagementServices()
	if err != nil {
		dstsLogger.Error("Failed to get the list of management services from the database!",
			zap.Error(err),
		)
		shutdownDeviceDatabase()
		return err
	}

	dstsLogger.Info("Connected to the device database!",
		zap.String("Database host: ", dbConfig.Host),
		zap.Int("Database port: ", dbConfig.Port),
	)
	return nil
}

func loadTlsCert(rootCertPath string) (*x509.CertPool, error) {
	certs := x509.NewCertPool()

	pemData, err := os.ReadFile(filepath.Clean(rootCertPath))
	if err != nil {
		dstsLogger.Error("Failed to read the root CA certificate file!",
			zap.String("CA certificate path", rootCertPath),
			zap.Error(err),
		)
		return nil, err
	}
	if !certs.AppendCertsFromPEM(pemData) {
		dstsLogger.Error("Failed to read the root CA certificate file!",
			zap.String("CA certificate path", rootCertPath),
			zap.Error(err),
		)
		return nil, errors.New("failed to append root ca cert")
	}

	return certs, nil
}
