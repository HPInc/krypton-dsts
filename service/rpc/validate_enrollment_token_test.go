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
	"google.golang.org/grpc/codes"
)

func TestValidateEnrollmentToken(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     uuid.NewString(),
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestValidateEnrollmentToken: CreateEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	validateRequest := &pb.ValidateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Token:   response.Token.GetToken(),
	}

	validateResponse, err := gClient.ValidateEnrollmentToken(gCtx, validateRequest)
	if err != nil {
		dstsLogger.Error("TestValidateEnrollmentToken: ValidateEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, validateResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", validateResponse))
}
