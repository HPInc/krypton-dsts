// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) GetSigningKey(ctx context.Context,
	request *pb.GetSigningKeyRequest) (*pb.GetSigningKeyResponse, error) {

	response := &pb.GetSigningKeyResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "GetSigningKey RPC successful",
			RequestId:       uuid.NewString(),
			ResponseTime:    timestamppb.Now(),
		},
		SigningKey: nil,
	}

	response.SigningKey = sts.GetTokenSigningKey()
	metrics.MetricGetSigningKeyRequests.Inc()
	return response, nil
}
