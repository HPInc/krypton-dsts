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

func DeviceAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	// Check if the contents of the POST were provided using URL encoding.
	if r.Header.Get(headerContentType) != contentTypeFormUrlEncoded {
		sendUnsupportedMediaTypeResponse(w)
		metrics.MetricDeviceAuthBadRequests.Inc()
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
		metrics.MetricDeviceAuthBadRequests.Inc()
		return
	}

	assertionType := r.Form.Get(paramClientAssertionType)
	assertion := r.Form.Get(paramClientAssertion)

	// Check if the required client_assertion_type and client_assertion request
	// parameters were specified in the request.
	if assertionType != sts.ClientAssertionType {
		dstsLogger.Error("Invalid client assertion type specified!",
			zap.String("Request ID", requestID),
			zap.String("Client assertion type: ", assertionType),
			zap.String("Client assertion: ", assertion),
		)
		sendBadRequestErrorResponse(w, requestID, reasonInvalidClientAssertionType)
		metrics.MetricDeviceAuthBadRequests.Inc()
		return
	}
	if assertion == "" {
		dstsLogger.Error("Client assertion type is not specified!",
			zap.String("Request ID", requestID),
			zap.String("Client assertion type: ", assertionType),
			zap.String("Client assertion: ", assertion),
		)
		sendBadRequestErrorResponse(w, requestID, reasonMissingClientAssertion)
		metrics.MetricDeviceAuthBadRequests.Inc()
		return
	}

	// Invoke the STS to parse and validate the provided client assertion. If
	// the assertion is valid, return a device access token.
	accessToken, expiresAt, err := sts.GetAccessTokenFromDeviceAssertion(requestID,
		assertion)
	if err != nil {
		// Check if presented assertion is expired or not valid yet.
		if errors.Is(err, sts.ErrAssertionExpired) {
			sendUnauthorizedResponse(w, requestID, reasonAssertionExpired)
			metrics.MetricDeviceAuthBadRequests.Inc()
			return
		}
		if errors.Is(err, sts.ErrAssertionNotValidYet) {
			sendUnauthorizedResponse(w, requestID, reasonAssertionNotValidYet)
			metrics.MetricDeviceAuthBadRequests.Inc()
			return
		}

		// Also, if the presented device certificate is not a valid
		// certificate.
		if errors.Is(err, sts.ErrInvalidDeviceCertificate) {
			sendUnauthorizedResponse(w, requestID, reasonInvalidDeviceCertificate)
			metrics.MetricDeviceAuthBadRequests.Inc()
			return
		}

		if errors.Is(err, db.ErrNotFound) {
			sendNotFoundErrorResponse(w)
			metrics.MetricDeviceAuthBadRequests.Inc()
			return
		}
		if errors.Is(err, db.ErrTombstoned) {
			sendResourceGoneErrorResponse(w, requestID, reasonTombstonedDevice)
			metrics.MetricDeviceAuthBadRequests.Inc()
			return
		}

		// Check if device authentication was blocked (i.e. device was either
		// disabled or marked lost)
		if errors.Is(err, db.ErrAuthnBlocked) {
			sendUnauthorizedResponse(w, requestID, reasonAuthenticationBlocked)
			metrics.MetricDeviceAuthBlocked.Inc()
			return
		}

		if errors.Is(err, db.ErrDatabaseBusy) {
			sendServerBusyErrorResponse(w)
			metrics.MetricDeviceAuthInternalErrors.Inc()
			return
		}

		sendInternalServerErrorResponse(w)
		metrics.MetricDeviceAuthInternalErrors.Inc()
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
		metrics.MetricDeviceAuthInternalErrors.Inc()
		return
	}

	metrics.MetricDeviceAuthResponses.Inc()
}
