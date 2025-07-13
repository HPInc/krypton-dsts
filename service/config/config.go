// package github.com/HPInc/krypton-dsts/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package config

const ServiceName = "HP Device Security Token Service"

type ServerConfig struct {
	// Hostname of the DSTS service.
	Host string `yaml:"host"`

	// Port on which the gRPC server is available.
	RpcPort int `yaml:"rpc_port"`

	// Port on which the REST server is available.
	RestPort int `yaml:"rest_port"`

	// Location of the registered applications configuration file.
	RegisteredAppConfigFile string `yaml:"registered_app_keys"`

	// Specifies whether to log all incoming REST requests to the debug log.
	DebugLogRestRequests bool `yaml:"log_rest_requests"`
}

// Structured logging configuration settings.
type LoggingConfig struct {
	// Default logging level to use.
	LogLevel string `yaml:"log_level"`
}

// CacheConfig - configuration settings for the device cache.
type CacheConfig struct {
	// Whether device caching is enabled.
	Enabled bool `yaml:"enabled"`

	// The hostname/IP address of the device cache.
	Host string `yaml:"cache_hostname"`

	// The port at which the cache is available.
	Port int `yaml:"cache_port"`

	// The Redis database number to be used for the device cache.
	CacheDatabase int `yaml:"cache_db"`

	// Password used to connect to the device cache.
	Password string
}

// DatabaseConfig - database settings for the device database (Postgres)
type DatabaseConfig struct {
	// The hostname/IP address of the database.
	Host string `yaml:"db_hostname"`

	// The port at which the database is available.
	Port int `yaml:"db_port"`

	// The name of the devices database in DSTS.
	DatabaseName string `yaml:"db_name"`

	// The username to use when connecting to the datastore.
	Username string `yaml:"user"`

	// Database password
	Password string

	// The path to the schema migration scripts for the identity database.
	SchemaMigrationScripts string `yaml:"schema"`

	// Whether to perform schema migration.
	SchemaMigrationEnabled bool `yaml:"migrate_enabled"`

	// Specifies whether database calls should be debug logged.
	DebugLoggingEnabled bool `yaml:"debug_enabled"`

	// Maximum number of open SQL connections
	MaxOpenConnections int `yaml:"max_open_connections"`

	// SSL mode to use for connections to the database.
	SslMode string `yaml:"ssl_mode"`

	// SSL root certificate to use for connections.
	SslRootCertificate string `yaml:"ssl_root_cert"`
}

type Config struct {
	ConfigFilePath string

	// Configuration settings for the gRPC server.
	ServerConfig `yaml:"server"`

	// Structured logging configuration settings.
	LoggingConfig `yaml:"logging"`

	// Device database configuration settings.
	DatabaseConfig `yaml:"database"`

	// Device cache related configuration settings.
	CacheConfig `yaml:"cache"`

	// Whether the service is running in test mode.
	TestMode bool `yaml:"test_mode"`
}
