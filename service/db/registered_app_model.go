// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	"github.com/HPInc/krypton-dsts/service/config"
	"go.uber.org/zap"
)

type RegisteredApp struct {
	// The ID of the registered app.
	AppId string `json:"app_id"`

	// The name of the management service.
	Name string `json:"name"`

	// The public key of the app that is registered with the DSTS.
	PublicKeyBytes []byte
	PublicKey      *rsa.PublicKey

	// Specifies whether the app is enabled. Tokens will not be issued to
	// disabled apps.
	IsEnabled bool `json:"enabled"`

	// Creation and modification timestamps for the device object.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Initialize all registered applications mentioned in the configuration file.
// If an invalid item is specified (eg. invalid public key) or an error occurs
// during processing, that item is skipped.
func initRegisteredApps(appConfig *[]config.RegisteredApp) error {
	var err error
	for _, item := range *appConfig {
		// The path to the keys file is specified in the DSTS app configuration file.
		if item.PublicKeyFilePath == "" {
			dstsLogger.Error("Invalid application keys file!",
				zap.String("App name:", item.Name),
				zap.String("Key file path:", item.PublicKeyFilePath),
			)
			return ErrInvalidRequest
		}

		// Read the public key for the application from its key file.
		_, err = os.Stat(item.PublicKeyFilePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// If the file does not exist, skip processing the entry.
				continue
			}
			dstsLogger.Error("Failed to check the existence of the application keys file!",
				zap.String("App name:", item.Name),
				zap.String("File path:", item.PublicKeyFilePath),
				zap.Error(err),
			)
			return err
		}

		rawBytes, err := os.ReadFile(item.PublicKeyFilePath)
		if err != nil {
			dstsLogger.Error("Failed to read the application keys file!",
				zap.String("App name:", item.Name),
				zap.String("File path:", item.PublicKeyFilePath),
				zap.Error(err),
			)
			return err
		}

		// PEM decode the RSA public key.
		block, _ := pem.Decode(rawBytes)
		if block == nil {
			dstsLogger.Error("Failed to PEM decode the data in the application keys file!")
			return ErrDecodePublicKey
		}
		if block.Type == publicKeyType {
			pKey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				dstsLogger.Error("Failed to parse public key from the application keys file!",
					zap.String("App name:", item.Name),
					zap.String("File path:", item.PublicKeyFilePath),
					zap.Error(err),
				)
				return err
			}

			// Register the application with the DSTS.
			newApp, err := NewRegisteredApp(item.Id, item.Name, item.IsEnabled,
				pKey.(*rsa.PublicKey))
			if err != nil {
				return err
			}

			err = newApp.AddOrUpdateRegisteredApp()
			if err != nil {
				dstsLogger.Error("Failed to update the registered app in the database!",
					zap.String("App ID:", item.Id),
					zap.String("App name:", item.Name),
					zap.Error(err),
				)
				return err
			}
		} else {
			dstsLogger.Error("Unexpected PEM block type encountered!",
				zap.String("Block type:", block.Type),
			)
			return ErrDecodePublicKey
		}
	}
	return nil
}
