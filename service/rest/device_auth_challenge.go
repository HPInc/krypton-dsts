// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"net/http"
	"time"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
)

type DeviceAuthenticationChallengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func DeviceAuthenticationChallengeHandler(w http.ResponseWriter,
	r *http.Request) {
	// Extract the request ID if specified.
	requestID := getRequestID(r)

	// Extract the device ID from the query parameter. If not specified,
	// reject the request as bad.
	deviceID := r.URL.Query().Get(paramDeviceID)
	if deviceID == "" {
		dstsLogger.Error("Device ID parameter was not specified!",
			zap.String("Request ID", requestID),
		)
		sendBadRequestErrorResponse(w, requestID, reasonDeviceIDNotSpecified)
		metrics.MetricDeviceAuthChallengeBadRequests.Inc()
		return
	}

	// Generate a challenge code and save it in the cache against the device ID.
	challenge := sts.NewAuthenticationChallenge()
	expiresAt, err := cache.AddDeviceAuthenticationChallenge(requestID,
		deviceID, challenge)
	if err != nil {
		sendInternalServerErrorResponse(w)
		metrics.MetricDeviceAuthChallengeInternalErrors.Inc()
		return
	}

	// Send the challenge code to the caller.
	err = sendJsonResponse(w, http.StatusOK, DeviceAuthenticationChallengeResponse{
		Challenge: challenge,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		metrics.MetricDeviceAuthChallengeInternalErrors.Inc()
		return
	}

	metrics.MetricDeviceAuthChallengeResponses.Inc()
}
