// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"time"

	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func unaryInterceptor(ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	// Calculate and report RPC latency metric when the interceptor is done.
	defer metrics.ReportLatencyMetric(metrics.MetricRPCLatency, start,
		info.FullMethod)

	h, err := handler(ctx, req)
	if err != nil {
		metrics.MetricRPCErrors.Inc()
	} else {
		metrics.MetricRPCsServed.Inc()
	}

	dstsLogger.Info("Processed gRPC request.",
		zap.String("Method:", info.FullMethod),
		zap.String("Duration:", time.Since(start).String()),
		zap.Error(err),
	)
	return h, err
}
