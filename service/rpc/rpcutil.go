// package github.com/HPInc/krypton-dsts/service/rpc
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rpc

import (
	pb "github.com/HPInc/krypton-dsts/dstsprotos"
	"github.com/google/uuid"
)

const (
	// DstsProtocolVersion - version of the DSTS' gRPC protocol.
	DstsProtocolVersion = "v1"
)

func isValidRequestHeader(header *pb.DstsRequestHeader) (string, bool) {
	// If the request didn't specify a header, reject it.
	if header == nil {
		dstsLogger.Error("Request header was not specified!")
		return "", false
	}

	// Ensure the DSTS protocol being requested is supported by this server.
	if header.ProtocolVersion != DstsProtocolVersion {
		dstsLogger.Error("Unsupported protocol version requested!")
		return "", false
	}

	// Extract the request ID, if it has been specified. If not, generate a
	// unique request ID to be used for logging information related to this
	// request.
	if header.RequestId == "" {
		return uuid.New().String(), true
	}

	return header.RequestId, true
}
