// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"testing"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/config"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/rest"
	"github.com/HPInc/krypton-dsts/service/sts"
)

const (
	bufSize = 1024 * 1024
)

var (
	gListener      *bufconn.Listener
	gClient        pb.DeviceSTSClient
	gConnection    *grpc.ClientConn
	gCtx           context.Context
	grpcTestServer *grpc.Server
)

func newDstsProtocolHeader() *pb.DstsRequestHeader {
	return &pb.DstsRequestHeader{
		ProtocolVersion: "v1",
		RequestId:       uuid.New().String(),
		RequestTime:     timestamppb.Now(),
	}
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return gListener.Dial()
}

func shutdownLogger() {
	_ = dstsLogger.Sync()
}

func initConnection() bool {
	var err error
	gCtx = context.Background()
	gConnection, err = grpc.DialContext(gCtx, "bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Printf("Failed to init bufnet connection: %v\n", err)
		return false
	}
	gClient = pb.NewDeviceSTSClient(gConnection)
	return true
}

func initTestRpcServer(logger *zap.Logger) {
	dstsLogger = logger

	gListener = bufconn.Listen(bufSize)
	grpcTestServer = grpc.NewServer()

	s := &DeviceSTSServer{}
	err := s.NewServer()
	if err != nil {
		dstsLogger.Error("Unable to configure DSTS server!",
			zap.Error(err),
		)
		_ = dstsLogger.Sync()
		os.Exit(2)
	}

	pb.RegisterDeviceSTSServer(grpcTestServer, s)

	go func() {
		err := grpcTestServer.Serve(gListener)
		if err != nil {
			_ = dstsLogger.Sync()
			log.Fatalf("CA test: Server exited with error: %v", err)
		}
	}()

	if false == initConnection() {
		_ = dstsLogger.Sync()
		log.Fatalf("CA test: Failed to initialize test environment. Exiting!")
	}
}

func shutdownTestRpcServer() {
	grpcTestServer.GracefulStop()
}

func TestMain(m *testing.M) {
	// Initialize logging for the test run.
	encoderCfg := zap.NewProductionEncoderConfig()
	core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg),
		zapcore.Lock(os.Stdout),
		zapcore.InfoLevel)
	dstsLogger = zap.New(core, zap.AddCaller())

	// Read and parse the configuration file.
	cfgMgr := config.NewConfigMgr(dstsLogger, config.ServiceName)
	if !cfgMgr.Load(false) {
		dstsLogger.Error("Failed to load configuration. Exiting!")
		shutdownLogger()
		os.Exit(2)
	}

	// Initialize the device database and perform any required schema
	// migrations. This also initializes the device cache.
	err := db.InitTest(dstsLogger, cfgMgr)
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

	// Initialize the DSTS test REST server.
	rest.InitTestServer(dstsLogger, cfgMgr)

	// Initialize a test RPC server using which the unit tests run.
	initTestRpcServer(dstsLogger)
	retCode := m.Run()

	// Cleanup after ourselves.
	shutdownTestRpcServer()
	shutdownLogger()
	fmt.Println("Finished running the DSTS RPC server unit tests!")
	os.Exit(retCode)
}
