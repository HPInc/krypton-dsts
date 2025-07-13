// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"testing"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestGetSigningKey(t *testing.T) {
	getRequest := &pb.GetSigningKeyRequest{}

	response, err := gClient.GetSigningKey(gCtx, getRequest)
	if err != nil {
		dstsLogger.Error("TestGetSigningKey: GetSigningKey RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}
