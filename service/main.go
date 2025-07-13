// package github.com/HPInc/krypton-dsts/service/main
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/rest"
	"github.com/HPInc/krypton-dsts/service/rpc"
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
)

var (
	// --version: displays versioning information.
	versionFlag = flag.Bool("version", false,
		"Print the version of the service and exit!")

	// --log_level: specify the logging level to use.
	logLevelFlag = flag.String("log_level", "",
		"Specify the logging level.")

	gitCommitHash string
	builtAt       string
	builtBy       string
	builtOn       string

	// Service configuration settings.
	cfgMgr *config.ConfigMgr
)

func printVersionInformation() {
	fmt.Printf("%s: version information\n", config.ServiceName)
	fmt.Printf("- Git commit hash: %s\n - Built at: %s\n - Built by: %s\n - Built on: %s\n",
		gitCommitHash, builtAt, builtBy, builtOn)
}

func main() {
	// Parse the command line flags.
	flag.Parse()
	if *versionFlag {
		printVersionInformation()
		return
	}

	// Initialize structured logging.
	initLogger(*logLevelFlag)
	metrics.RegisterPrometheusMetrics()

	// Read and parse the configuration file.
	cfgMgr = config.NewConfigMgr(dstsLogger, config.ServiceName)
	if !cfgMgr.Load(false) {
		dstsLogger.Error("Failed to load configuration. Exiting!")
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the device database and perform any required schema
	// migrations. This also initializes the device cache.
	err := db.Init(dstsLogger, cfgMgr)
	if err != nil {
		dstsLogger.Error("Failed to initialize the device database!",
			zap.Error(err),
		)
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the security token service.
	err = sts.Init(dstsLogger)
	if err != nil {
		dstsLogger.Error("Failed to initialize the security token service!",
			zap.Error(err),
		)
		db.Shutdown()
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the REST server and listen for REST requests on a separate
	// goroutine. Report fatal errors via the error channel.
	go rest.Init(dstsLogger, cfgMgr)

	// Initialize the gRPC server and start listening for RPC requests at the
	// DSTS endpoint.
	err = rpc.Init(dstsLogger, cfgMgr)
	if err != nil {
		dstsLogger.Error("Failed to initialize the gRPC server!",
			zap.Error(err),
		)
		db.Shutdown()
		shutdownLogger()
		os.Exit(2)
	}

	// Shutdown the connection to the device database and cache.
	db.Shutdown()
	shutdownLogger()
	fmt.Printf("%s: Goodbye!", config.ServiceName)
}
