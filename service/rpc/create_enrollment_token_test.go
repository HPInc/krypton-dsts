// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"testing"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

func TestCreateEnrollmentToken(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     testTenantID,
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateEnrollmentToken: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
	if response.Header.Status == uint32(codes.OK) {
		assertEqual(t, response.Token.ExpiryTime.AsTime().Sub(response.Token.IssuedTime.AsTime()).Round(time.Hour*1),
			time.Duration(30*24)*time.Hour)
	}
}

func TestCreateEnrollmentToken_NoTenantID(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateEnrollmentToken_NoTenantID: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestCreateEnrollmentTokenDefaultLifetime(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               uuid.NewString(),
		TokenLifetimeDays: 30,
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateEnrollmentTokenDefaultLifetime: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
	if response.Header.Status == uint32(codes.OK) {
		assertEqual(t, response.Token.ExpiryTime.AsTime().Sub(response.Token.IssuedTime.AsTime()).Round(time.Hour*1),
			time.Duration(30*24)*time.Hour)
	}
}

func TestCreateEnrollmentTokenMaxLifetime(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               uuid.NewString(),
		TokenLifetimeDays: -1,
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateEnrollmentTokenMaxLifetime: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
	if response.Header.Status == uint32(codes.OK) {
		assertEqual(t, response.Token.ExpiryTime.AsTime().Sub(response.Token.IssuedTime.AsTime()).Round(time.Hour*1),
			time.Duration(365*5*24)*time.Hour)
	}
}

func TestCreateEnrollmentTokenCustomLifetime(t *testing.T) {
	createRequest := &pb.CreateEnrollmentTokenRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               uuid.NewString(),
		TokenLifetimeDays: 60,
	}

	response, err := gClient.CreateEnrollmentToken(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateEnrollmentTokenCustomLifetime: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
	if response.Header.Status == uint32(codes.OK) {
		assertEqual(t, response.Token.ExpiryTime.AsTime().Sub(response.Token.IssuedTime.AsTime()).Round(time.Hour*1),
			time.Duration(60*24)*time.Hour)
	}
}
