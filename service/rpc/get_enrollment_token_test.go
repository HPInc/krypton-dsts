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

func TestGetEnrollmentToken(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     uuid.NewString(),
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestGetEnrollmentToken: CreateEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	t.Logf("Response from device STS: %+v\n", response)

	getRequest := &pb.GetEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     createRequest.Tid,
	}

	getResponse, err := gClient.GetEnrollmentToken(gCtx, getRequest)
	if err != nil {
		dstsLogger.Error("TestGetEnrollmentToken: GetEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}

func TestGetEnrollmentToken_NoTenantID(t *testing.T) {
	getRequest := &pb.GetEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
	}

	getResponse, err := gClient.GetEnrollmentToken(gCtx, getRequest)
	if err != nil {
		dstsLogger.Error("TestGetEnrollmentToken_NoTenantID: GetEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}

func TestGetEnrollmentToken_UnknownTenantID(t *testing.T) {
	getRequest := &pb.GetEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     uuid.NewString(),
	}

	getResponse, err := gClient.GetEnrollmentToken(gCtx, getRequest)
	if err != nil {
		dstsLogger.Error("TestGetEnrollmentToken_UnknownTenantID: GetEnrollmentToken RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.NotFound))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}
