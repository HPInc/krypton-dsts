// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) GetAppAuthenticationChallenge(ctx context.Context,
	request *pb.AppAuthenticationChallengeRequest) (*pb.AppAuthenticationChallengeResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidGetAppAuthenticationChallengeResponse(requestID)
		return response, nil
	}

	if request.AppId == "" {
		dstsLogger.Error("Invalid app ID specified in the request!")
		response := invalidGetAppAuthenticationChallengeResponse(requestID)
		return response, nil
	}

	// Generate a challenge code and save it in the cache against the device ID.
	challenge := sts.NewAuthenticationChallenge()
	expiresAt, err := cache.AddDeviceAuthenticationChallenge(requestID,
		request.AppId, challenge)
	if err != nil {
		response := internalErrorGetAppAuthenticationChallengeResponse(requestID)
		metrics.MetricDeviceAuthChallengeInternalErrors.Inc()
		return response, nil
	}

	response := successGetAppAuthenticationChallengeResponse(requestID, challenge, expiresAt)
	return response, nil
}

func invalidGetAppAuthenticationChallengeResponse(
	requestID string) *pb.AppAuthenticationChallengeResponse {
	response := &pb.AppAuthenticationChallengeResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "GetAppAuthenticationChallenge RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationChallengeBadRequests.Inc()
	return response
}

func successGetAppAuthenticationChallengeResponse(
	requestID string, challenge string,
	expiresAt time.Time) *pb.AppAuthenticationChallengeResponse {
	response := &pb.AppAuthenticationChallengeResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "GetAppAuthenticationChallenge RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Challenge: challenge,
		ExpiresAt: timestamppb.New(expiresAt),
	}

	metrics.MetricAppAuthenticationChallenge.Inc()
	return response
}

func internalErrorGetAppAuthenticationChallengeResponse(
	requestID string) *pb.AppAuthenticationChallengeResponse {
	response := &pb.AppAuthenticationChallengeResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "GetAppAuthenticationChallenge RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricAppAuthenticationChallengeInternalErrors.Inc()
	return response
}
