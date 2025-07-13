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

func TestDeleteDevice(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestDeleteDevice: Failed to create test device certificate",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		Tid:               testTenantID,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteDevice: CreateDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	deleteRequest := &pb.DeleteDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      testTenantID,
		DeviceId: createRequest.DeviceId,
	}

	deleteResponse, err := gClient.DeleteDevice(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteDevice: DeleteDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}

func TestDeleteDevice_NoTenantID(t *testing.T) {
	deleteRequest := &pb.DeleteDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		DeviceId: uuid.NewString(),
	}

	deleteResponse, err := gClient.DeleteDevice(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteDevice_NoTenantID: DeleteDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}

func TestDeleteDevice_NoDeviceID(t *testing.T) {
	deleteRequest := &pb.DeleteDeviceRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     testTenantID,
	}

	deleteResponse, err := gClient.DeleteDevice(gCtx, deleteRequest)
	if err != nil {
		dstsLogger.Error("TestDeleteDevice_NoDeviceID: DeleteDevice RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, deleteResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", deleteResponse))
}
