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
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) ValidateEnrollmentToken(ctx context.Context,
	request *pb.ValidateEnrollmentTokenRequest) (*pb.ValidateEnrollmentTokenResponse, error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidValidateEnrollmentTokenResponse(requestID)
		return response, nil
	}

	// Ensure the request specified an enrollment token to be validated.
	if request.Token == "" {
		dstsLogger.Error("Enrollment token was not specified",
			zap.String("Request ID:", requestID),
		)
		response := invalidValidateEnrollmentTokenResponse(requestID)
		return response, nil
	}

	tenantID, err := sts.ValidateEnrollmentToken(requestID, request.Token)
	if err != nil {
		dstsLogger.Error("Failed to validate enrollment token",
			zap.String("Request ID:", requestID),
			zap.Error(err),
		)
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyValidateEnrollmentTokenResponse(requestID), nil
		}
		return accessDeniedValidateEnrollmentTokenResponse(requestID), nil
	}

	response := successValidateEnrollmentTokenResponse(requestID, tenantID)
	return response, nil
}

func invalidValidateEnrollmentTokenResponse(
	requestID string) *pb.ValidateEnrollmentTokenResponse {
	response := &pb.ValidateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "ValidateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		IsValid: false,
	}

	metrics.MetricValidateEnrollmentTokenBadRequests.Inc()
	return response
}

func successValidateEnrollmentTokenResponse(requestID string,
	tenantID string) *pb.ValidateEnrollmentTokenResponse {
	response := &pb.ValidateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "ValidateEnrollmentToken RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Tid:     tenantID,
		IsValid: true,
	}

	metrics.MetricEnrollmentTokenValidated.Inc()
	return response
}

func accessDeniedValidateEnrollmentTokenResponse(
	requestID string) *pb.ValidateEnrollmentTokenResponse {
	response := &pb.ValidateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Unauthenticated),
			StatusMessage:   "ValidateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		IsValid: false,
	}

	metrics.MetricValidateEnrollmentTokenAccessDenied.Inc()
	return response
}

func serverBusyValidateEnrollmentTokenResponse(
	requestID string) *pb.ValidateEnrollmentTokenResponse {
	response := &pb.ValidateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "ValidateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		IsValid: false,
	}

	metrics.MetricValidateEnrollmentTokenServerErrors.Inc()
	return response
}
