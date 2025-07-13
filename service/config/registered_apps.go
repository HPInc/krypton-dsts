// package github.com/HPInc/krypton-dsts/service/config
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package config

import (
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

type RegisteredAppConfig struct {
	// Registered application config.
	Apps []RegisteredApp `yaml:"registered_apps"`
}

// Configuration settings for applications registered with the device STS.
// These applications can authenticate themselves and request app tokens.
type RegisteredApp struct {
	// Unique identifier for the registered application.
	Id string `yaml:"id"`

	// Name of the registered application.
	Name string `yaml:"name"`

	// Whether the application is enabled.
	IsEnabled bool `yaml:"enabled"`

	// Path to the key file in which the public key of this app is stored.
	PublicKeyFilePath string `yaml:"public_key_file"`
}

// Load configuration information for registered apps from the YAML configuration
// file.
func (c *ConfigMgr) LoadRegisteredAppConfig(configFilePath string) bool {
	var filename string = defaultRegisteredAppsConfigFilePath

	// Check if the default configuration file has been overridden using the
	// environment variable.
	if configFilePath != "" {
		dstsLogger.Info("Using configuration file specified by environment variable.",
			zap.String("App configuration file:", configFilePath),
		)
		filename = configFilePath
	}

	// Open the configuration file for parsing.
	fh, err := os.Open(filename)
	if err != nil {
		dstsLogger.Error("Failed to load registered application configuration file!",
			zap.String("App configuration file:", filename),
			zap.Error(err),
		)
		return false
	}

	// Read the configuration file and unmarshal the YAML.
	decoder := yaml.NewDecoder(fh)
	err = decoder.Decode(&c.appConfig)
	if err != nil {
		dstsLogger.Error("Failed to parse registered application configuration file!",
			zap.String("App configuration file:", filename),
			zap.Error(err),
		)
		_ = fh.Close()
		return false
	}

	_ = fh.Close()
	dstsLogger.Info("Parsed registered application configuration from the configuration file!",
		zap.String("Configuration file:", filename),
	)

	return true
}
