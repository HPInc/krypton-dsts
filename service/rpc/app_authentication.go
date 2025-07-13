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
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) AuthenticateApp(ctx context.Context,
	request *pb.AppAuthenticationRequest) (*pb.AppAuthenticationResponse, error) {
	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidAuthenticateAppResponse(requestID)
		return response, nil
	}

	// Check if the required client_assertion_type and client_assertion request
	// parameters were specified in the request.
	if (request.AssertionType != sts.ClientAssertionType) || (request.Assertion == "") {
		dstsLogger.Error("Client assertion type or assertion parameters not specified!",
			zap.String("Request ID: ", requestID),
			zap.String("Client assertion type: ", request.AssertionType),
			zap.String("Client assertion: ", request.Assertion),
		)
		response := invalidAuthenticateAppResponse(requestID)
		return response, nil
	}

	if request.AppId == "" {
		dstsLogger.Error("App ID parameter was not specified!",
			zap.String("Request ID: ", requestID),
		)
		response := invalidAuthenticateAppResponse(requestID)
		return response, nil
	}

	// Invoke the STS to parse and validate the provided client assertion. If
	// the assertion is valid, return an app access token.
	accessToken, expiresAt, err := sts.GetAccessTokenFromAppAssertion(requestID,
		request.AppId, request.Assertion)
	if err != nil {
		dstsLogger.Error("Failed to generate access token from assertion!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)

		// Check if app authentication was blocked (i.e. app was disabled).
		if (errors.Is(err, db.ErrAuthnBlocked)) ||
			(errors.Is(err, db.ErrNotFound)) ||
			(errors.Is(err, sts.ErrAssertionExpired)) ||
			(errors.Is(err, sts.ErrAssertionNotValidYet)) {
			return unauthorizedAuthenticateAppResponse(requestID), nil
		}

		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyAuthenticateAppResponse(requestID), nil
		}

		return internalErrorAuthenticateAppResponse(requestID), nil
	}

	response := successAuthenticateAppResponse(requestID, accessToken, expiresAt)
	return response, nil
}

func invalidAuthenticateAppResponse(
	requestID string) *pb.AppAuthenticationResponse {
	response := &pb.AppAuthenticationResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "AuthenticateApp RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationBadRequests.Inc()
	return response
}

func serverBusyAuthenticateAppResponse(requestID string) *pb.AppAuthenticationResponse {
	response := &pb.AppAuthenticationResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "AuthenticateApp RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationBadRequests.Inc()
	return response
}

func unauthorizedAuthenticateAppResponse(
	requestID string) *pb.AppAuthenticationResponse {
	response := &pb.AppAuthenticationResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Unauthenticated),
			StatusMessage:   "AuthenticateApp RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationInternalErrors.Inc()
	return response
}

func successAuthenticateAppResponse(
	requestID string, accessToken string,
	expiresAt time.Time) *pb.AppAuthenticationResponse {
	response := &pb.AppAuthenticationResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "AuthenticateApp RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		AccessToken: accessToken,
		ExpiresAt:   timestamppb.New(expiresAt),
	}

	metrics.MetricAppAuthenticationRequests.Inc()
	return response
}

func internalErrorAuthenticateAppResponse(
	requestID string) *pb.AppAuthenticationResponse {
	response := &pb.AppAuthenticationResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "AuthenticateApp RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationInternalErrors.Inc()
	return response
}
