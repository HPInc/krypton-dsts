// package github.com/HPInc/krypton-dsts/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package config

import (
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

type envSetting struct {
	isSecret bool
	value    interface{}
}

// loadEnvironmentVariableOverrides - check values specified for supported
// environment variables. These can be used to override configuration settings
// specified in the config file.
func (c *ConfigMgr) loadEnvironmentVariableOverrides() {
	m := map[string]envSetting{
		// Server configuration settings
		"DSTS_SERVER":                     {value: &c.config.ServerConfig.Host},
		"DSTS_RPC_PORT":                   {value: &c.config.ServerConfig.RpcPort},
		"DSTS_REST_PORT":                  {value: &c.config.ServerConfig.RestPort},
		"DSTS_REGISTERED_APP_CONFIG_FILE": {value: &c.config.ServerConfig.RegisteredAppConfigFile},
		"DSTS_REST_DEBUG_ENABLED":         {value: &c.config.ServerConfig.DebugLogRestRequests},

		// Cache configuration settings
		"DSTS_CACHE_ENABLED":  {value: &c.config.CacheConfig.Enabled},
		"DSTS_CACHE_HOST":     {value: &c.config.CacheConfig.Host},
		"DSTS_CACHE_PORT":     {value: &c.config.CacheConfig.Port},
		"DSTS_CACHE_PASSWORD": {isSecret: true, value: &c.config.CacheConfig.Password},

		// Database configuration settings
		"DSTS_DB_HOST":            {value: &c.config.DatabaseConfig.Host},
		"DSTS_DB_PORT":            {value: &c.config.DatabaseConfig.Port},
		"DSTS_DB_NAME":            {value: &c.config.DatabaseConfig.DatabaseName},
		"DSTS_DB_USER":            {value: &c.config.DatabaseConfig.Username},
		"DSTS_DB_PASSWORD":        {isSecret: true, value: &c.config.DatabaseConfig.Password},
		"DSTS_DB_SCHEMA_LOCATION": {value: &c.config.DatabaseConfig.SchemaMigrationScripts},
		"DSTS_DB_DEBUG_ENABLED":   {value: &c.config.DatabaseConfig.DebugLoggingEnabled},
		"DSTS_DB_MIGRATE_ENABLED": {value: &c.config.DatabaseConfig.SchemaMigrationEnabled},
		"DSTS_DB_SSL_MODE":        {value: &c.config.DatabaseConfig.SslMode},
		"DSTS_DB_SSL_ROOT_CERT":   {value: &c.config.DatabaseConfig.SslRootCertificate},
	}
	for k, v := range m {
		e := os.Getenv(k)
		if e != "" {
			dstsLogger.Info("Overriding configuration from environment variable.",
				zap.String("variable: ", k),
				zap.String("value: ", getLoggableValue(v.isSecret, e)))
			v := v
			replaceConfigValue(os.Getenv(k), &v)
		}
	}
}

// envValue will be non empty as this function is private to file
func replaceConfigValue(envValue string, t *envSetting) {
	switch t.value.(type) {
	case *string:
		*t.value.(*string) = envValue
	case *[]string:
		valSlice := strings.Split(envValue, ",")
		for i := range valSlice {
			valSlice[i] = strings.TrimSpace(valSlice[i])
		}
		*t.value.(*[]string) = valSlice
	case *bool:
		b, err := strconv.ParseBool(envValue)
		if err != nil {
			dstsLogger.Error("Bad bool value in env")
		} else {
			*t.value.(*bool) = b
		}
	case *int:
		i, err := strconv.Atoi(envValue)
		if err != nil {
			dstsLogger.Error("Bad integer value in env",
				zap.Error(err))
		} else {
			*t.value.(*int) = i
		}
	default:
		dstsLogger.Error("There was a bad type map in env override",
			zap.String("value", envValue))
	}
}

func getLoggableValue(isSecret bool, value string) string {
	if isSecret {
		return "***"
	}
	return value
}
