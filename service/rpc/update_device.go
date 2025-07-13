// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	"context"
	"errors"
	"strings"
	"time"

	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/HPInc/krypton-dsts/service/common"
	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *DeviceSTSServer) UpdateDevice(ctx context.Context,
	request *pb.UpdateDeviceRequest) (*pb.UpdateDeviceResponse, error) {

	// Validate the request header and extract the request identifier for
	// end-to-end request tracing.
	requestID, ok := isValidRequestHeader(request.Header)
	if !ok {
		dstsLogger.Error("Invalid request header specified!")
		response := invalidUpdateDeviceResponse(requestID)
		return response, nil
	}

	// Ensure the request specified a tenant ID.
	if (request.Tid == "") || (request.DeviceId == "") {
		dstsLogger.Error("Tenant ID was not specified",
			zap.String("Request ID", requestID),
		)
		response := invalidUpdateDeviceResponse(requestID)
		return response, nil
	}

	mask := request.GetUpdateMask()
	var updateMap = make(map[string]interface{})
	for _, field := range mask.GetPaths() {
		switch strings.ToLower(field) {

		case "enabled", "is_enabled":
			updateMap[db.UpdateFieldIsEnabled] = request.Update.IsEnabled

		case "lost", "is_lost":
			updateMap[db.UpdateFieldIsLost] = request.Update.IsLost

		case "cert", "certificate", "device_certificate":
			if request.Update.DeviceCertificate == nil {
				dstsLogger.Error("Received invalid request to update device certificate",
					zap.String("Request ID", requestID),
					zap.String("Device ID", request.DeviceId),
					zap.String("Tenant ID", request.Tid),
				)
				response := invalidUpdateDeviceResponse(requestID)
				return response, nil
			}

			// Parse the provided device certificate.
			deviceCert, err := common.ParseCertificate(
				request.Update.DeviceCertificate)
			if err != nil {
				dstsLogger.Error("Failed to parse the provided device certificate",
					zap.String("Request ID", requestID),
					zap.String("Device ID", request.DeviceId),
					zap.String("Tenant ID", request.Tid),
					zap.Error(err),
				)
				response := invalidUpdateDeviceResponse(requestID)
				return response, nil
			}

			// Perform some validation checks on the provided certificate.
			err = common.VerifyCertificate(deviceCert)
			if err != nil {
				dstsLogger.Error("Verification checks failed for the device certificate",
					zap.String("Request ID", requestID),
					zap.String("Device ID", request.DeviceId),
					zap.String("Tenant ID", request.Tid),
					zap.Error(err),
				)
				response := invalidUpdateDeviceResponse(requestID)
				return response, nil
			}
			if !common.VerifyDeviceIDInCertificateCommonName(deviceCert, request.DeviceId) {
				dstsLogger.Error("Device ID specified in the request doesn't match that in the device certificate",
					zap.String("Request ID", requestID),
					zap.String("Device ID", request.DeviceId),
					zap.String("Tenant ID", request.Tid),
					zap.Error(err),
				)
				response := invalidUpdateDeviceResponse(requestID)
				return response, nil
			}

			// Generate a SHA256 hash which serves as the certificate thumbprint.
			updateMap[db.UpdateFieldCertificateThumbprint] = common.GetCertificateThumbprint(deviceCert)
			updateMap[db.UpdateFieldCertificateIssuedAt] = deviceCert.NotBefore
			updateMap[db.UpdateFieldCertificateExpiresAt] = deviceCert.NotAfter

		default:
			dstsLogger.Error("Received invalid update request mask",
				zap.String("Request ID", requestID),
				zap.String("Device ID", request.DeviceId),
				zap.String("Tenant ID", request.Tid),
				zap.String("Update mask", field),
			)
		}
	}

	// Check if the update has no valid updates specified.
	if len(updateMap) == 0 {
		dstsLogger.Error("No valid updates found in the request!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", request.DeviceId),
			zap.String("Tenant ID", request.Tid),
		)
		return invalidUpdateDeviceResponse(requestID), nil
	}

	updateMap["UpdatedAt"] = time.Now()
	err := db.UpdateDevice(requestID, request.DeviceId, request.Tid,
		updateMap)
	if err != nil {
		dstsLogger.Error("Failed to update the specified device!",
			zap.String("Request ID", requestID),
			zap.String("Device ID", request.DeviceId),
			zap.String("Tenant ID", request.Tid),
			zap.Error(err),
		)
		if errors.Is(err, db.ErrNotFound) {
			return notFoundUpdateDeviceResponse(requestID), nil
		}
		if errors.Is(err, db.ErrDatabaseBusy) {
			return serverBusyUpdateDeviceResponse(requestID), nil
		}
		return internalErrorUpdateDeviceResponse(requestID), nil
	}

	return successUpdateDeviceResponse(requestID), nil
}

func invalidUpdateDeviceResponse(requestID string) *pb.UpdateDeviceResponse {
	metrics.MetricUpdateDeviceBadRequests.Inc()
	return &pb.UpdateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.InvalidArgument),
			StatusMessage:   "UpdateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func successUpdateDeviceResponse(requestID string) *pb.UpdateDeviceResponse {
	metrics.MetricDeviceUpdated.Inc()
	return &pb.UpdateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.OK),
			StatusMessage:   "UpdateDevice RPC was successful",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
		UpdateTime: timestamppb.Now(),
	}
}

func notFoundUpdateDeviceResponse(requestID string) *pb.UpdateDeviceResponse {
	metrics.MetricUpdateDeviceNotFoundErrors.Inc()
	return &pb.UpdateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.NotFound),
			StatusMessage:   "UpdateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func internalErrorUpdateDeviceResponse(requestID string) *pb.UpdateDeviceResponse {
	metrics.MetricUpdateDeviceInternalErrors.Inc()
	return &pb.UpdateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.Internal),
			StatusMessage:   "UpdateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}

func serverBusyUpdateDeviceResponse(requestID string) *pb.UpdateDeviceResponse {
	metrics.MetricUpdateDeviceInternalErrors.Inc()
	return &pb.UpdateDeviceResponse{
		Header: &pb.DstsResponseHeader{
			ProtocolVersion: DstsProtocolVersion,
			Status:          uint32(codes.ResourceExhausted),
			StatusMessage:   "UpdateDevice RPC failed",
			RequestId:       requestID,
			ResponseTime:    timestamppb.Now(),
		},
	}
}
