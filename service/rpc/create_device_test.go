// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"reflect"
	"testing"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

const (
	DeviceCertificateLifetimeYears = 1
	KeySize                        = 4096
)

var (
	testTenantID, testTenantName, testTenantDomain string
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		return
	}
	t.Errorf("Received: %v (type %v), Expected: %v (type %v)", a,
		reflect.TypeOf(a), b, reflect.TypeOf(b))
}

func init() {
	testTenantID = uuid.New().String()
	testTenantName = "Unreliable Corporation"
	testTenantDomain = "unreliable.com"
}

func TestCreateDevice(t *testing.T) {

	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestCreateDevice: Failed to create test device certificate:",
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
		dstsLogger.Error("TestCreateDevice: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestCreateDevice_NoTenantID(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestCreateDevice: Failed to create test device certificate:",
			zap.Error(err))
		t.Fail()
		return
	}

	createRequest := &pb.CreateDeviceRequest{
		Header:            newDstsProtocolHeader(),
		Version:           DstsProtocolVersion,
		DeviceId:          deviceID,
		DeviceCertificate: deviceCert,
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateDevice: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestCreateDevice_ValidManagementService(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestCreateDevice: Failed to create test device certificate:",
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
		ManagementService: "hpcem",
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateDevice: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestCreateDevice_InvalidManagementService(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestCreateDevice: Failed to create test device certificate:",
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
		ManagementService: "stargazer",
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateDevice: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.InvalidArgument))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}

func TestCreateDevice_ValidHardwareHash(t *testing.T) {
	deviceCert, deviceID, _, err := createTestDeviceCertificate(testTenantID,
		testTenantName, "")
	if err != nil {
		dstsLogger.Error("TestCreateDevice: Failed to create test device certificate:",
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
		HardwareHash:      uuid.NewString(),
	}

	response, err := gClient.CreateDevice(gCtx, createRequest)
	if err != nil {
		dstsLogger.Error("TestCreateDevice: RPC failed",
			zap.Error(err))
		t.Fail()
		return
	}

	assertEqual(t, response.Header.Status, uint32(codes.OK))
	dstsLogger.Info("Response from device STS:",
		zap.Any("Response:", response))
}
