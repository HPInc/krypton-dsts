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

func TestListDevices(t *testing.T) {
	listRequest := &pb.ListDevicesRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     testTenantID,
	}

	listResponse, err := gClient.ListDevices(gCtx, listRequest)
	if err != nil {
		dstsLogger.Error("TestListDevices: ListDevices RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, listResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", listResponse))
}
