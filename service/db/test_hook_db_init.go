// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	testPublicKeyFileFormat = "%s/%s_key.pub"
)

func InitTest(logger *zap.Logger, cfgMgr *config.ConfigMgr) error {
	var (
		testKeyCount = 5
		testApps     []config.RegisteredApp
	)

	// Do nothing, if invoked outside of test mode.
	if !cfgMgr.IsTestModeEnabled() {
		return nil
	}

	err := Init(logger, cfgMgr)
	if err != nil {
		logger.Error("Failed to initialize the database!",
			zap.Error(err))
		return err
	}

	tempDir, err := os.MkdirTemp(os.TempDir(), "keys_*")
	if err != nil {
		dstsLogger.Error("Failed to create a temporary directory for testing!",
			zap.Error(err),
		)
		return err
	}

	testApps = make([]config.RegisteredApp, testKeyCount)

	// First create a key for the scheduler app.
	appId := "bebc5cbf-acc0-431f-8c4e-c582dc2489e2"

	for i := 0; i < testKeyCount; i++ {
		publicKeyFileName := fmt.Sprintf(testPublicKeyFileFormat, tempDir, appId)

		// Generate a test RSA key pair for the scheduler app. Write the public
		// key to a file in the tmp folder.
		testKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			dstsLogger.Error("Failed to generate a test key pair for the app.",
				zap.Error(err))
			return err
		}

		err = encodePublicKeyToFile(&testKey.PublicKey, publicKeyFileName)
		if err != nil {
			dstsLogger.Error("Failed to PEM encode the public key for the app.",
				zap.Error(err))
			return err
		}

		testApps[i] = config.RegisteredApp{
			Id:                appId,
			Name:              fmt.Sprintf("TestApp %s", appId),
			IsEnabled:         true,
			PublicKeyFilePath: publicKeyFileName,
		}
		appId = uuid.NewString()
	}

	err = initRegisteredApps(&testApps)
	if err != nil {
		dstsLogger.Error("Failed to register test applications!",
			zap.Error(err),
		)
		return err
	}

	err = os.RemoveAll(tempDir)
	if err != nil {
		dstsLogger.Error("Failed to delete the temporary directory after testing!",
			zap.String("Directory", tempDir),
			zap.Error(err),
		)
		return err
	}
	return nil
}
