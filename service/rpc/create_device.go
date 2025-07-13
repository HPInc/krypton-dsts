// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"errors"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) CreateDevice(ctx context.Context,
	request *pb.CreateDeviceRequest) (*pb.CreateDeviceResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}

	// Ensure the request specified a tenant ID and device ID.
	if (request.Tid == "") || (request.DeviceId == "") {
		dstsLogger.Error("Tenant ID or device ID were not specified",
			zap.String("Request ID", requestID),
		)
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}

	if request.DeviceCertificate == nil {
		dstsLogger.Error("Device certificate was not provided",
			zap.String("Request ID", requestID),
		)
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}

	// Parse the provided device certificate.
	deviceCert, err := common.ParseCertificate(request.DeviceCertificate)
	if err != nil {
		dstsLogger.Error("Failed to parse the provided device certificate",
			zap.String("Request ID:", requestID),
			zap.Error(err),
		)
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}

	// Perform some validation checks on the provided certificate.
	err = common.VerifyCertificate(deviceCert)
	if err != nil {
		dstsLogger.Error("Verification checks failed for the device certificate",
			zap.String("Request ID", requestID),
			zap.Error(err),
		)
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}
	if !common.VerifyDeviceIDInCertificateCommonName(deviceCert, request.DeviceId) {
		dstsLogger.Error("Device ID specified in the request doesn't match that in the device certificate",
			zap.String("Request ID", requestID),
			zap.Error(err),
		)
		response := invalidCreateDeviceResponse(requestID)
		return response, nil
	}

	// Generate a SHA256 hash which serves as the certificate thumbprint. Set
	// the service ID to the name of the management service specified in the
	// request.
	newDevice := db.Device{
		DeviceId:              request.DeviceId,
		TenantId:              request.Tid,
		IsEnabled:             true,
		IsLost:                false,
		CertificateIssuedAt:   deviceCert.NotBefore,
		CertificateThumbprint: common.GetCertificateThumbprint(deviceCert),
		CertificateExpiresAt:  deviceCert.NotAfter,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		ServiceId:             request.ManagementService,
		HardwareHash:          request.HardwareHash,
	}

	// Invoke the DB APIs to create a device object and store information
	// about the device in the database.
	err = newDevice.CreateDevice(requestID)
	if err != nil {
		dstsLogger.Error("Failed to add the device to the database!",
			zap.Error(err),
		)
		if errors.Is(err, db.ErrInvalidRequest) {
			// The specified management service was not found or is
			// invalid.
			return invalidCreateDeviceResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDuplicateEntry) {
			// A device with the specified device ID already exists in the
			// database.
			return duplicateCreateDeviceResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyCreateDeviceResponse(requestID), nil
		}

		return internalErrorCreateDeviceResponse(requestID), nil
	}

	response := successCreateDeviceResponse(requestID)
	return response, nil
}

func invalidCreateDeviceResponse(
	requestID string) *pb.CreateDeviceResponse {
	response := &pb.CreateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "CreateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceBadRequests.Inc()
	return response
}

func duplicateCreateDeviceResponse(
	requestID string) *pb.CreateDeviceResponse {
	response := &pb.CreateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.AlreadyExists),
			StatusMessage:   "CreateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceAlreadyExistsErrors.Inc()
	return response
}

func successCreateDeviceResponse(
	requestID string) *pb.CreateDeviceResponse {
	response := &pb.CreateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "CreateDevice RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		CreateTime: timestamppb.Now(),
	}

	metrics.MetricDeviceCreated.Inc()
	return response
}

func internalErrorCreateDeviceResponse(
	requestID string) *pb.CreateDeviceResponse {
	response := &pb.CreateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "CreateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceInternalErrors.Inc()
	return response
}

func serverBusyCreateDeviceResponse(
	requestID string) *pb.CreateDeviceResponse {
	response := &pb.CreateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "CreateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricCreateDeviceInternalErrors.Inc()
	return response
}
