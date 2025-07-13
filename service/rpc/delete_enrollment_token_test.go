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

func TestDeleteEnrollmentToken(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     uuid.NewString(),
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteEnrollmentToken: CreateEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	deleteRequest := &pb.DeleteEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     createRequest.Tid,
	}

	deleteResponse, err := gClient.DeleteEnrollmentToken(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteEnrollmentToken: DeleteEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}

func TestDeleteEnrollmentToken_NoTenantID(t *testing.T) {
	deleteRequest := &pb.DeleteEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
	}

	deleteResponse, err := gClient.DeleteEnrollmentToken(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteEnrollmentToken_NoTenantID: DeleteEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}

func TestDeleteEnrollmentToken_UnknownTenantID(t *testing.T) {
	deleteRequest := &pb.DeleteEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     uuid.NewString(),
	}

	deleteResponse, err := gClient.DeleteEnrollmentToken(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteEnrollmentToken_UnknownTenantID: DeleteEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.NotFound))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}
