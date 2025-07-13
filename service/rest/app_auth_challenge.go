// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"net/http"

	"github.com/HPInc/krypton-dsts/service/cache"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
)

func AppAuthenticationChallengeHandler(w http.ResponseWriter,
	r *http.Request) {
	// Extract the request ID if specified.
	requestID := getRequestID(r)

	// Extract the app ID from the query parameter. If not specified,
	// reject the request as bad.
	appID := r.URL.Query().Get(paramAppID)
	if appID == "" {
		dstsLogger.Error("App ID parameter was not specified!",
			zap.String("Request ID", requestID),
		)
		sendBadRequestErrorResponse(w, requestID, reasonAppIDNotSpecified)
		metrics.MetricAppAuthChallengeBadRequests.Inc()
		return
	}

	// Generate a challenge code and save it in the cache against the app ID.
	challenge := sts.NewAuthenticationChallenge()
	expiresAt, err := cache.AddDeviceAuthenticationChallenge(requestID,
		appID, challenge)
	if err != nil {
		sendInternalServerErrorResponse(w)
		metrics.MetricAppAuthChallengeInternalErrors.Inc()
		return
	}

	// Send the challenge code to the caller.
	err = sendJsonResponse(w, http.StatusOK, DeviceAuthenticationChallengeResponse{
		Challenge: challenge,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		metrics.MetricAppAuthChallengeInternalErrors.Inc()
		return
	}

	metrics.MetricAppAuthChallengeResponses.Inc()
}
