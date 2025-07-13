// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"fmt"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxLengthPingMessage = 25
)

func (s *DeviceSTSServer) Ping(ctx context.Context,
	request *pb.PingRequest) (*pb.PingResponse, error) {

	if len(request.Message) > maxLengthPingMessage {
		return nil, fmt.Errorf("invalid ping request - message too long")
	}

	metrics.MetricPingRequests.Inc()
	return &pb.PingResponse{
		Message:      request.Message,
		ResponseTime: timestamppb.Now()}, nil
}
