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

func (s *DeviceSTSServer) DeleteDevice(ctx context.Context,
	request *pb.DeleteDeviceRequest) (*pb.DeleteDeviceResponse, error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		return invalidDeleteDeviceResponse(requestID), nil
	}

	// Ensure the request specified a tenant ID and device ID.
	if (request.Tid == "") || (request.DeviceId == "") {
		dstsLogger.Error("Tenant ID or device ID were not specified",
			zap.String("Request ID:", requestID),
		)
		return invalidDeleteDeviceResponse(requestID), nil
	}

	err := db.DeleteDevice(requestID, request.Tid, request.DeviceId)
	if err != nil {
		dstsLogger.Error("Failed to delete device information!",
			zap.String("Request ID: ", requestID),
			zap.String("Device ID: ", request.DeviceId),
			zap.String("Tenant ID: ", request.Tid),
		)
		if errors.Is(err, db.ErrNotFound) {
			return notFoundDeleteDeviceResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyDeleteDeviceResponse(requestID), nil
		}
		return internalErrorDeleteDeviceResponse(requestID), nil
	}

	return successDeleteDeviceResponse(requestID), nil
}

func invalidDeleteDeviceResponse(requestID string) *pb.DeleteDeviceResponse {
	metrics.MetricDeleteDeviceBadRequests.Inc()
	return &pb.DeleteDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "DeleteDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func successDeleteDeviceResponse(requestID string) *pb.DeleteDeviceResponse {
	metrics.MetricDeviceDeleted.Inc()
	return &pb.DeleteDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "DeleteDevice RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		DeleteTime: timestamppb.Now(),
	}
}

func notFoundDeleteDeviceResponse(requestID string) *pb.DeleteDeviceResponse {
	metrics.MetricDeleteDeviceNotFoundErrors.Inc()
	return &pb.DeleteDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.NotFound),
			StatusMessage:   "DeleteDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func internalErrorDeleteDeviceResponse(requestID string) *pb.DeleteDeviceResponse {
	metrics.MetricDeleteDeviceInternalErrors.Inc()
	return &pb.DeleteDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "DeleteDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func serverBusyDeleteDeviceResponse(requestID string) *pb.DeleteDeviceResponse {
	metrics.MetricDeleteDeviceInternalErrors.Inc()
	return &pb.DeleteDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "DeleteDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}
