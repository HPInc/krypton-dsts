// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"errors"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) ListDevices(ctx context.Context,
	request *pb.ListDevicesRequest) (*pb.ListDevicesResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidListDevicesResponse(requestID)
		return response, nil
	}

	// Ensure the request specified a tenant ID.
	if request.Tid == "" {
		dstsLogger.Error("Tenant ID was not specified",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", request.Tid),
		)
		response := invalidListDevicesResponse(requestID)
		return response, nil
	}

	device := db.Device{}
	pagination := &db.Paginator{
		Limit: int(request.PageSize),
		Page:  int(request.PageNumber),
	}
	foundDevices, err := device.ListDevicesPaginated(requestID, request.Tid,
		request.Filter, pagination)
	if err != nil {
		dstsLogger.Error("Failed to retrieve list of devices for tenant!",
			zap.String("Request ID", requestID),
			zap.String("Tenant ID", request.Tid),
			zap.Error(err),
		)
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyListDevicesResponse(requestID), nil
		}
		return internalErrorListDevicesResponse(requestID), nil
	}

	response := &pb.ListDevicesResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "ListDevices RPC successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		Devices:  nil,
		NextPage: 0,
	}
	response.NextPage, err = common.ToInt32(pagination.Page + 1)
	if err != nil {
		return internalErrorListDevicesResponse(requestID), nil
	}
	for _, entry := range foundDevices {
		tmp := &pb.Device{
			Tid:                   entry.TenantId,
			DeviceId:              entry.DeviceId,
			IsEnabled:             entry.IsEnabled,
			IsLost:                entry.IsLost,
			CertificateThumbprint: entry.CertificateThumbprint,
			ExpiryTime:            timestamppb.New(entry.CertificateExpiresAt),
			ManagementService:     device.ServiceId,
			HardwareHash:          device.HardwareHash,
		}
		response.Devices = append(response.Devices, tmp)
	}

	metrics.MetricDevicesListed.Inc()
	return response, nil
}

func invalidListDevicesResponse(requestID string) *pb.ListDevicesResponse {
	response := &pb.ListDevicesResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "ListDevices RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricListDevicesBadRequests.Inc()
	return response
}

func internalErrorListDevicesResponse(requestID string) *pb.ListDevicesResponse {
	response := &pb.ListDevicesResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "ListDevices RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricListDevicesInternalErrors.Inc()
	return response
}

func serverBusyListDevicesResponse(requestID string) *pb.ListDevicesResponse {
	response := &pb.ListDevicesResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "ListDevices RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}

	metrics.MetricListDevicesInternalErrors.Inc()
	return response
}
