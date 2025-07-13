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

func TestGetDevice(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		t.Errorf("TestGetDevice: Failed to create test device certificate: %v", err)
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
		t.Errorf("TestGetDevice: CreateDevice RPC failed %v", err)
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))

	getRequest := &pb.GetDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		Tid:      testTenantID,
		DeviceId: createRequest.DeviceId,
	}

	getResponse, err := gClient.GetDevice(gCtx, getRequest)
	if err != nil {
		t.Errorf("TestGetDevice: GetDevice RPC failed %v", err)
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}

func TestGetDevice_NoTenantID(t *testing.T) {
	getRequest := &pb.GetDeviceRequest{
		Header:   newDstsProtocolHeader(),
		Version:  DstsProtocolVersion,
		DeviceId: uuid.NewString(),
	}

	getResponse, err := gClient.GetDevice(gCtx, getRequest)
	if err != nil {
		t.Errorf("TestGetDevice_NoTenantID: GetDevice RPC failed %v", err)
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}

func TestGetDevice_NoDeviceID(t *testing.T) {
	getRequest := &pb.GetDeviceRequest{
		Header:  newDstsProtocolHeader(),
		Version: DstsProtocolVersion,
		Tid:     testTenantID,
	}

	getResponse, err := gClient.GetDevice(gCtx, getRequest)
	if err != nil {
		t.Errorf("TestGetDevice_NoDeviceID: GetDevice RPC failed %v", err)
		return
	}

	assertEqual(t, getResponse.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", getResponse))
}
