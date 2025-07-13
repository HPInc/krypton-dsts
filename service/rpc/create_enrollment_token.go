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

func (s *DeviceSTSServer) CreateEnrollmentToken(ctx context.Context,
	request *pb.CreateEnrollmentTokenRequest) (*pb.CreateEnrollmentTokenResponse, error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		return invalidCreateEnrollmentTokenResponse(requestID), nil
	}

	// Ensure the request specified a tenant ID.
	if request.Tid == "" {
		dstsLogger.Error("Tenant ID was not specified",
			zap.String("Request ID:", requestID),
		)
		return invalidCreateEnrollmentTokenResponse(requestID), nil
	}

	// Issue a new enrollment token for the requested tenant.
	enrollmentToken, expiresAt, err := sts.NewEnrollmentToken(requestID,
		request.Tid, request.TokenLifetimeDays)
	if err != nil {
		dstsLogger.Error("Failed to generate the enrollment token!",
			zap.String("Request ID:", requestID),
			zap.String("Tenant ID:", request.Tid),
			zap.Error(err),
		)
		return internalErrorCreateEnrollmentTokenResponse(requestID), nil
	}

	newToken := db.EnrollmentToken{
		TenantId:       request.Tid,
		Token:          enrollmentToken,
		TokenExpiresAt: expiresAt,
	}

	// Invoke the DB APIs to create an enrollment token object and store
	// it in the database.
	err = newToken.CreateEnrollmentToken(requestID)
	if err != nil {
		dstsLogger.Error("Failed to add the enrollment token to the database!",
			zap.String("Request ID:", requestID),
			zap.String("Tenant ID:", request.Tid),
			zap.Error(err),
		)

		if errors.Is(err, db.ErrDuplicateEntry) {
			return duplicateKeyCreateEnrollmentTokenResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyCreateEnrollmentTokenResponse(requestID), nil
		}

		return internalErrorCreateEnrollmentTokenResponse(requestID), nil
	}

	return successCreateEnrollmentTokenResponse(requestID, &newToken), nil
}

func invalidCreateEnrollmentTokenResponse(
	requestID string) *pb.CreateEnrollmentTokenResponse {
	metrics.MetricCreateEnrollmentTokenBadRequests.Inc()
	return &pb.CreateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "CreateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func duplicateKeyCreateEnrollmentTokenResponse(
	requestID string) *pb.CreateEnrollmentTokenResponse {
	metrics.MetricCreateEnrollmentTokenAlreadyExistsErrors.Inc()
	return &pb.CreateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.AlreadyExists),
			StatusMessage:   "CreateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func successCreateEnrollmentTokenResponse(
	requestID string, token *db.EnrollmentToken) *pb.CreateEnrollmentTokenResponse {
	metrics.MetricEnrollmentTokenCreated.Inc()
	return &pb.CreateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "CreateEnrollmentToken RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Token: &pb.EnrollmentToken{
			Token:      token.Token,
			IssuedTime: timestamppb.New(token.CreatedAt),
			ExpiryTime: timestamppb.New(token.TokenExpiresAt),
		},
	}
}

func internalErrorCreateEnrollmentTokenResponse(
	requestID string) *pb.CreateEnrollmentTokenResponse {
	metrics.MetricCreateEnrollmentTokenInternalErrors.Inc()
	return &pb.CreateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "CreateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func serverBusyCreateEnrollmentTokenResponse(
	requestID string) *pb.CreateEnrollmentTokenResponse {
	metrics.MetricCreateEnrollmentTokenInternalErrors.Inc()
	return &pb.CreateEnrollmentTokenResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "CreateEnrollmentToken RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}
