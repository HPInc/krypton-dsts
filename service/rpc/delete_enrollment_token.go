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

func (s *DeviceSTSServer) DeleteEnrollmentToken(ctx context.Context,
	request *pb.DeleteEnrollmentTokenRequest) (*pb.DeleteEnrollmentTokenResponse, error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidDeleteEnrollmentTokenResponse(requestID)
		return response, nil
	}

	// Ensure the request specified a tenant ID.
	if request.Tid == "" {
		dstsLogger.Error("Tenant ID was not specified",
			zap.String("Request ID", requestID),
		)
		response := invalidDeleteEnrollmentTokenResponse(requestID)
		return response, nil
	}

	var d db.EnrollmentToken
	err := d.DeleteEnrollmentToken(requestID, request.Tid)
	if err != nil {
		dstsLogger.Error("Failed to delete enrollment token!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", request.Tid),
		)
		if errors.Is(err, db.ErrNotFound) {
			return notFoundDeleteEnrollmentTokenResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyDeleteEnrollmentTokenResponse(requestID), nil
		}
		return internalErrorDeleteEnrollmentTokenResponse(requestID), nil
	}

	response := successDeleteEnrollmentTokenResponse(requestID)
	return response, nil
}

func invalidDeleteEnrollmentTokenResponse(
	requestID string) *pb.DeleteEnrollmentTokenResponse {
	response := &pb.DeleteEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "DeleteEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteEnrollmentTokenBadRequests.Inc()
	return response
}

func successDeleteEnrollmentTokenResponse(
	requestID string) *pb.DeleteEnrollmentTokenResponse {
	response := &pb.DeleteEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "DeleteEnrollmentToken RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		DeleteTime: timestamppb.Now(),
	}

	metrics.MetricEnrollmentTokenDeleted.Inc()
	return response
}

func internalErrorDeleteEnrollmentTokenResponse(
	requestID string) *pb.DeleteEnrollmentTokenResponse {
	response := &pb.DeleteEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "DeleteEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteEnrollmentTokenInternalErrors.Inc()
	return response
}

func serverBusyDeleteEnrollmentTokenResponse(
	requestID string) *pb.DeleteEnrollmentTokenResponse {
	response := &pb.DeleteEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "DeleteEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteEnrollmentTokenInternalErrors.Inc()
	return response
}

func notFoundDeleteEnrollmentTokenResponse(
	requestID string) *pb.DeleteEnrollmentTokenResponse {
	response := &pb.DeleteEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.NotFound),
			StatusMessage:   "DeleteEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricDeleteEnrollmentTokenNotFound.Inc()
	return response
}
