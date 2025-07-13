// package github.com/HPInc/krypton-dsts/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package config

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

const (
	// Path to the configuration YAML file.
	defaultConfigFilePath = "config.yaml"

	// Path to the registered apps configuration YAML file.
	defaultRegisteredAppsConfigFilePath = "registered_apps.yaml"
)

var (
	dstsLogger *zap.Logger
)

type ConfigMgr struct {
	config      Config
	appConfig   RegisteredAppConfig
	serviceName string
}

// NewConfigMgr - initalize a new configuration manager instance.
func NewConfigMgr(logger *zap.Logger, serviceName string) *ConfigMgr {
	dstsLogger = logger
	return &ConfigMgr{
		serviceName: serviceName,
	}
}

// Load configuration information from the YAML configuration file.
func (c *ConfigMgr) Load(testModeEnabled bool) bool {
	var filename string = defaultConfigFilePath

	// Check if the default configuration file has been overridden using the
	// environment variable.
	c.config.ConfigFilePath = os.Getenv("DSTS_CONFIG_LOCATION")
	if c.config.ConfigFilePath != "" {
		dstsLogger.Info("Using configuration file specified by command line switch.",
			zap.String("Configuration file:", c.config.ConfigFilePath),
		)
		filename = c.config.ConfigFilePath
	}

	// Open the configuration file for parsing.
	fh, err := os.Open(filename)
	if err != nil {
		dstsLogger.Error("Failed to load configuration file!",
			zap.String("Configuration file:", filename),
			zap.Error(err),
		)
		return false
	}

	// Read the configuration file and unmarshal the YAML.
	decoder := yaml.NewDecoder(fh)
	err = decoder.Decode(&c.config)
	if err != nil {
		dstsLogger.Error("Failed to parse configuration file!",
			zap.String("Configuration file:", filename),
			zap.Error(err),
		)
		_ = fh.Close()
		return false
	}

	_ = fh.Close()
	dstsLogger.Info("Parsed configuration from the configuration file!",
		zap.String("Configuration file:", filename),
	)

	// Load any configuration overrides specified using environment variables.
	c.loadEnvironmentVariableOverrides()

	testModeEnvVar := os.Getenv("TEST_MODE")
	if (testModeEnvVar == "enabled") || (testModeEnabled) {
		c.config.TestMode = true
		fmt.Println("DSTS service is running in test mode with test hooks enabled.")
	}

	c.Display()
	return c.LoadRegisteredAppConfig(c.config.RegisteredAppConfigFile)
}

// Return the server configuration settings.
func (c *ConfigMgr) GetServerConfig() *ServerConfig {
	return &c.config.ServerConfig
}

// Return the cache configuration settings.
func (c *ConfigMgr) GetCacheConfig() *CacheConfig {
	return &c.config.CacheConfig
}

// Return the database configuration settings.
func (c *ConfigMgr) GetDatabaseConfig() *DatabaseConfig {
	return &c.config.DatabaseConfig
}

// Return the logging configuration settings.
func (c *ConfigMgr) GetLoggingConfig() *LoggingConfig {
	return &c.config.LoggingConfig
}

func (c *ConfigMgr) GetRegisteredApps() *[]RegisteredApp {
	return &c.appConfig.Apps
}

// Check if the service is running in test mode.
func (c *ConfigMgr) IsTestModeEnabled() bool {
	return c.config.TestMode
}

func (c *ConfigMgr) IsDebugLoggingRestRequestsEnabled() bool {
	return c.config.ServerConfig.DebugLogRestRequests
}

// Display the configuration information parsed from the configuration file in
// the structured log.
func (c *ConfigMgr) Display() {
	dstsLogger.Info("HP Device Security Token Service - current configuration",
		zap.String(" - Service name:", c.serviceName),
		zap.Bool(" - Test mode enabled:", c.config.TestMode),
	)
	dstsLogger.Info("Server settings",
		zap.String(" - Hostname:", c.config.ServerConfig.Host),
		zap.Int(" - RPC Port:", c.config.ServerConfig.RpcPort),
		zap.Int(" - Rest Port:", c.config.ServerConfig.RestPort),
	)
	dstsLogger.Info("Logging settings",
		zap.String(" - Log level:", c.config.LoggingConfig.LogLevel),
	)
	dstsLogger.Info("Database settings",
		zap.String(" - Host:", c.config.DatabaseConfig.Host),
		zap.Int(" - Port:", c.config.DatabaseConfig.Port),
		zap.String(" - User name:", c.config.DatabaseConfig.Username),
		zap.String(" - Database migration scripts:", c.config.DatabaseConfig.SchemaMigrationScripts),
		zap.Bool(" - Database migration enabled:", c.config.DatabaseConfig.SchemaMigrationEnabled),
		zap.Bool(" - Debug logging enabled:", c.config.DatabaseConfig.DebugLoggingEnabled),
		zap.String(" - SSL mode:", c.config.DatabaseConfig.SslMode),
		zap.String(" - SSL root certificate:", c.config.DatabaseConfig.SslRootCertificate),
	)
	dstsLogger.Info("Cache settings",
		zap.Bool(" - Caching enabled:", c.config.CacheConfig.Enabled),
		zap.String(" - Host:", c.config.CacheConfig.Host),
		zap.Int(" - Port:", c.config.CacheConfig.Port),
		zap.Int(" - Database:", c.config.CacheConfig.CacheDatabase),
	)
}
