// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestPing(t *testing.T) {
	pingRequest := &pb.PingRequest{
		Message: "ping",
	}

	response, err := gClient.Ping(gCtx, pingRequest)
	if err != nil {
		dstsLogger.Error("TestPing: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestPingMessageTooLong(t *testing.T) {
	pingRequest := &pb.PingRequest{
		Message: uuid.NewString(),
	}

	response, err := gClient.Ping(gCtx, pingRequest)
	if err == nil {
		dstsLogger.Error("TestPing: RPC did not fail as expected",
			zap.Error(err))
		t.Fail()
		return
	}

	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}
