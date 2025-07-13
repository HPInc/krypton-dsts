// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"errors"
	"net/http"

	"github.com/HPInc/krypton-dsts/service/db"
	"github.com/HPInc/krypton-dsts/service/metrics"
	"github.com/HPInc/krypton-dsts/service/sts"
	"go.uber.org/zap"
)

func AppAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the contents of the POST were provided using URL encoding.
	if r.Header.Get(headerContentType) != contentTypeFormUrlEncoded {
		sendUnsupportedMediaTypeResponse(w)
		metrics.MetricAppAuthBadRequests.Inc()
		return
	}

	// Extract the request ID if specified.
	requestID := getRequestID(r)

	err := r.ParseForm()
	if err != nil {
		dstsLogger.Error("Failed to parse the request form!",
			zap.String("Request ID", requestID),
			zap.Error(err),
		)
		sendBadRequestErrorResponse(w, requestID, reasonRequestParsingFailed)
		metrics.MetricAppAuthBadRequests.Inc()
		return
	}

	assertionType := r.Form.Get(paramClientAssertionType)
	assertion := r.Form.Get(paramClientAssertion)
	appId := r.Form.Get(paramAppID)

	// Check if the required client_assertion_type and client_assertion request
	// parameters were specified in the request.
	if assertionType != sts.ClientAssertionType {
		dstsLogger.Error("Invalid client assertion type specified!",
			zap.String("Request ID", requestID),
			zap.String("Client assertion type: ", assertionType),
			zap.String("Client assertion: ", assertion),
		)
		sendBadRequestErrorResponse(w, requestID, reasonInvalidClientAssertionType)
		metrics.MetricAppAuthBadRequests.Inc()
		return
	}
	if assertion == "" {
		dstsLogger.Error("Client assertion type is not specified!",
			zap.String("Request ID", requestID),
			zap.String("Client assertion type: ", assertionType),
			zap.String("Client assertion: ", assertion),
		)
		sendBadRequestErrorResponse(w, requestID, reasonMissingClientAssertion)
		metrics.MetricAppAuthBadRequests.Inc()
		return
	}

	if appId == "" {
		dstsLogger.Error("App ID parameter was not specified!",
			zap.String("Request ID", requestID),
		)
		sendBadRequestErrorResponse(w, requestID, reasonAppIDNotSpecified)
		metrics.MetricAppAuthBadRequests.Inc()
		return
	}

	// Invoke the STS to parse and validate the provided client assertion. If
	// the assertion is valid, return an app access token.
	accessToken, expiresAt, err := sts.GetAccessTokenFromAppAssertion(requestID,
		appId, assertion)
	if err != nil {
		dstsLogger.Error("Failed to generate access token from assertion!",
			zap.String("Request ID", requestID),
			zap.Error(err),
		)

		// Check if presented assertion is expired or not valid yet.
		if errors.Is(err, sts.ErrAssertionExpired) {
			sendUnauthorizedResponse(w, requestID, reasonAssertionExpired)
			metrics.MetricAppAuthBadRequests.Inc()
			return
		}
		if errors.Is(err, sts.ErrAssertionNotValidYet) {
			sendUnauthorizedResponse(w, requestID, reasonAssertionNotValidYet)
			metrics.MetricAppAuthBadRequests.Inc()
			return
		}

		// Check if app authentication was blocked (i.e. app was disabled).
		if errors.Is(err, db.ErrAuthnBlocked) {
			sendUnauthorizedResponse(w, requestID, reasonAuthenticationBlocked)
			metrics.MetricAppAuthBlocked.Inc()
			return
		}

		if errors.Is(err, db.ErrNotFound) {
			sendNotFoundErrorResponse(w)
			metrics.MetricAppAuthBadRequests.Inc()
			return
		}

		if errors.Is(err, db.ErrDatabaseBusy) {
			sendServerBusyErrorResponse(w)
			metrics.MetricAppAuthInternalErrors.Inc()
			return
		}

		sendInternalServerErrorResponse(w)
		metrics.MetricAppAuthInternalErrors.Inc()
		return
	}

	// Return the generated access token to the caller.
	err = sendJsonResponse(w, http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		dstsLogger.Error("Failed to encode JSON response!",
			zap.String("Request ID", requestID),
			zap.Error(err),
		)
		metrics.MetricAppAuthInternalErrors.Inc()
		return
	}

	metrics.MetricAppAuthResponses.Inc()
}
