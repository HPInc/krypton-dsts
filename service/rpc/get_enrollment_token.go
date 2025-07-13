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

func (s *DeviceSTSServer) GetEnrollmentToken(ctx context.Context,
	request *pb.GetEnrollmentTokenRequest) (*pb.GetEnrollmentTokenResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidGetEnrollmentTokenResponse(requestID)
		return response, nil
	}

	// Ensure the request specified a tenant ID and device ID.
	if request.Tid == "" {
		dstsLogger.Error("Tenant ID was not specified",
			zap.String("Request ID:", requestID),
		)
		response := invalidGetEnrollmentTokenResponse(requestID)
		return response, nil
	}

	// Query the database for an enrollment token for the tenant.
	token, err := db.GetEnrollmentTokenForTenant(requestID, request.Tid)
	if err != nil {
		dstsLogger.Error("Failed to get enrollment token information!",
			zap.String("Request ID: ", requestID),
			zap.String("Tenant ID: ", request.Tid),
			zap.Error(err),
		)

		// Check if an enrollment token was not found for the specified
		// tenant in the database.
		if errors.Is(err, db.ErrNotFound) {
			return notFoundGetEnrollmentTokenResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyGetEnrollmentTokenResponse(requestID), nil
		}

		response := internalErrorGetEnrollmentTokenResponse(requestID)
		return response, nil
	}

	response := successGetEnrollmentTokenResponse(requestID, token)
	return response, nil
}

func invalidGetEnrollmentTokenResponse(
	requestID string) *pb.GetEnrollmentTokenResponse {
	response := &pb.GetEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "GetEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricGetEnrollmentTokenBadRequests.Inc()
	return response
}

func successGetEnrollmentTokenResponse(
	requestID string, token *db.EnrollmentToken) *pb.GetEnrollmentTokenResponse {
	response := &pb.GetEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "GetEnrollmentToken RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Token: &pb.EnrollmentToken{
			Token:      token.Token,
			IssuedTime: timestamppb.New(token.CreatedAt),
			ExpiryTime: timestamppb.New(token.TokenExpiresAt),
		},
	}

	metrics.MetricEnrollmentTokenGet.Inc()
	return response
}

func internalErrorGetEnrollmentTokenResponse(
	requestID string) *pb.GetEnrollmentTokenResponse {
	response := &pb.GetEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "GetEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricGetEnrollmentTokenInternalErrors.Inc()
	return response
}

func notFoundGetEnrollmentTokenResponse(
	requestID string) *pb.GetEnrollmentTokenResponse {
	response := &pb.GetEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.NotFound),
			StatusMessage:   "GetEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
	metrics.MetricGetEnrollmentTokenNotFound.Inc()
	return response
}

func serverBusyGetEnrollmentTokenResponse(
	requestID string) *pb.GetEnrollmentTokenResponse {
	response := &pb.GetEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "GetEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
	metrics.MetricGetEnrollmentTokenNotFound.Inc()
	return response
}
