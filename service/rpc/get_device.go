// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"errors"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) GetDevice(ctx context.Context,
	request *pb.GetDeviceRequest) (*pb.GetDeviceResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		return invalidGetDeviceResponse(requestID), nil
	}

	// Ensure the request specified a tenant ID and device ID.
	if (request.Tid == "") || (request.DeviceId == "") {
		dstsLogger.Error("Tenant ID or device ID were not specified",
			zap.String("Request ID", requestID),
		)
		return invalidGetDeviceResponse(requestID), nil
	}

	dev, err := db.GetDevice(requestID, request.Tid, request.DeviceId)
	if err != nil {
		dstsLogger.Error("Failed to get device information!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", request.DeviceId),
			zap.String("Tenant ID", request.Tid),
			zap.Error(err),
		)
		if errors.Is(err, db.ErrNotFound) {
			return notFoundGetDeviceResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyGetDeviceResponse(requestID), nil
		}
		return internalErrorGetDeviceResponse(requestID), nil
	}

	return successGetDeviceResponse(requestID, dev), nil
}

func invalidGetDeviceResponse(requestID string) *pb.GetDeviceResponse {
	metrics.MetricGetDeviceBadRequests.Inc()
	return &pb.GetDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "GetDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func successGetDeviceResponse(
	requestID string, device *db.Device) *pb.GetDeviceResponse {
	metrics.MetricDeviceGet.Inc()
	return &pb.GetDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "GetDevice RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Device: &pb.Device{
			Tid:                   device.TenantId,
			DeviceId:              device.DeviceId,
			IsEnabled:             device.IsEnabled,
			IsLost:                device.IsLost,
			CertificateThumbprint: device.CertificateThumbprint,
			IssuedTime:            timestamppb.New(device.CertificateIssuedAt),
			ExpiryTime:            timestamppb.New(device.CertificateExpiresAt),
			ManagementService:     device.ServiceId,
			HardwareHash:          device.HardwareHash,
		},
	}
}

func notFoundGetDeviceResponse(requestID string) *pb.GetDeviceResponse {
	metrics.MetricGetDeviceNotFoundErrors.Inc()
	return &pb.GetDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.NotFound),
			StatusMessage:   "GetDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func serverBusyGetDeviceResponse(requestID string) *pb.GetDeviceResponse {
	metrics.MetricGetDeviceInternalErrors.Inc()
	return &pb.GetDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "GetDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func internalErrorGetDeviceResponse(requestID string) *pb.GetDeviceResponse {
	metrics.MetricGetDeviceInternalErrors.Inc()
	return &pb.GetDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "GetDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}
