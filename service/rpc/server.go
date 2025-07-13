// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/HPInc/krypton-dsts/service/config"
	"go.uber.org/zap"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

var (
	dstsLogger *zap.Logger
	dstsConfig *config.ServerConfig
)

const (
// TODO: re-enable TLS after certificate generation is in place.
// caCertPath    = "config/ca.pem"
// caKeyFilePath = "config/ca.key"
)

// DeviceSTSServer - Connection and other state information for the Device STS.
type DeviceSTSServer struct {
	// Device STS gRPC server.
	dstsgRPCServer *grpc.Server

	pb.UnimplementedDeviceSTSServer

	// Signal handling to support SIGTERM and SIGINT.
	errChannel  chan error
	stopChannel chan os.Signal
}

// Init - initialize and start the DSTS gRPC server
func Init(logger *zap.Logger, cfgMgr *config.ConfigMgr) error {
	dstsLogger = logger
	dstsConfig = cfgMgr.GetServerConfig()

	s := &DeviceSTSServer{}
	err := s.NewServer()
	if err != nil {
		dstsLogger.Error("Unable to configure gRPC server. Error!",
			zap.Error(err),
		)
		fmt.Println("Failed to configure gRPC server. Exiting!")
		return err
	}

	err = s.startServing()
	if err != nil {
		dstsLogger.Error("DSTS gRPC server failed to start up.",
			zap.String("Hostname:", dstsConfig.Host),
			zap.Int("Port:", dstsConfig.RpcPort),
			zap.Error(err),
		)
		fmt.Println("Failed to start DSTS gRPC server. Exiting!")
		return err
	}

	s.awaitTermination()
	return nil
}

func (s *DeviceSTSServer) NewServer() error {
	// Handle SIGTERM and SIGINT.
	s.errChannel = make(chan error)
	s.stopChannel = make(chan os.Signal, 1)
	signal.Notify(s.stopChannel, syscall.SIGINT, syscall.SIGTERM)

	var defaultKeepAliveParams = keepalive.ServerParameters{
		Time:    20 * time.Second,
		Timeout: 5 * time.Second,
	}

	// TODO: re-enable TLS after certificate generation is in place.
	/*
		creds, err := credentials.NewServerTLSFromFile(caCertPath, caKeyFilePath)
		if err != nil {
			dstsLogger.Error("Failed to generate credentials for TLS!",
				zap.Error(err),
			)
			return err
		}
	*/

	// Initialize and register the gRPC server.
	s.dstsgRPCServer = grpc.NewServer(
		//	grpc.Creds(creds),
		grpc.KeepaliveParams(defaultKeepAliveParams),
		grpc.UnaryInterceptor(unaryInterceptor),
	)

	pb.RegisterDeviceSTSServer(s.dstsgRPCServer, s)
	return nil
}

// Start listening on the configured port. Creates a separate goroutine to
// serve gRPC requests.
func (s *DeviceSTSServer) startServing() error {
	go s.listenAndServe()
	return nil
}

// Goroutine to listen for and serve gRPC requests.
func (s *DeviceSTSServer) listenAndServe() {
	// Start the server and listen to the specified gRPC port.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d",
		dstsConfig.RpcPort))
	if err != nil {
		dstsLogger.Error("Failed to initialize a listener for the gRPC server!",
			zap.Error(err),
		)
		s.errChannel <- err
		return
	}

	// Start accepting incoming connection requests.
	err = s.dstsgRPCServer.Serve(listener)
	if err != nil {
		dstsLogger.Error("Failed to start serving incoming gRPC requests!",
			zap.Error(err),
		)
		s.errChannel <- err
		return
	}

	dstsLogger.Info("Serving gRPC requests.",
		zap.Int("Port", dstsConfig.RpcPort),
	)
}

// Wait for a signal to shutdown the gRPC server and cleanup.
func (s *DeviceSTSServer) awaitTermination() {
	// Block until we receive either an OS signal, or encounter a server
	// fatal error and need to terminate.
	select {
	case err := <-s.errChannel:
		dstsLogger.Error("Shutting down due to a fatal error.",
			zap.Error(err),
		)
	case sig := <-s.stopChannel:
		dstsLogger.Error("Received an OS signal and shutting down.",
			zap.String("Signal:", sig.String()),
		)
	}

	// Cleanup.
	s.dstsgRPCServer.GracefulStop()
}
