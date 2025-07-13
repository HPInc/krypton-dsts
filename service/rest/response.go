// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

type TokenResponse struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type FailedRequestError struct {
	HttpCode uint   `json:"code"`
	Message  string `json:"message"`
}

const (
	reasonRequestParsingFailed       = "error parsing request parameters"
	reasonInvalidClientAssertionType = "invalid client assertion type specified"
	reasonMissingClientAssertion     = "client assertion type is not specified"
	reasonAssertionExpired           = "presented client assertion is expired"
	reasonAssertionNotValidYet       = "presented client assertion is not yet valid"
	reasonInvalidDeviceCertificate   = "invalid device certificate presented"
	reasonAuthenticationBlocked      = "device authentication is blocked for this device"
	reasonAppIDNotSpecified          = "app_id parameter was not specified"
	reasonDeviceIDNotSpecified       = "device_id parameter was not specified"
	reasonTombstonedDevice           = "device is no longer enrolled and has been deleted"
)

func sendInternalServerErrorResponse(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError),
		http.StatusInternalServerError)
}

func sendBadRequestErrorResponse(w http.ResponseWriter, requestID string,
	reason string) {
	err := sendJsonResponse(w, http.StatusBadRequest, FailedRequestError{
		HttpCode: http.StatusBadRequest,
		Message:  reason,
	})
	if err != nil {
		dstsLogger.Error("Failed to encode JSON response!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
	}
}

func sendResourceGoneErrorResponse(w http.ResponseWriter, requestID string,
	reason string) {
	err := sendJsonResponse(w, http.StatusGone, FailedRequestError{
		HttpCode: http.StatusGone,
		Message:  reason,
	})
	if err != nil {
		dstsLogger.Error("Failed to encode JSON response!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
	}
}

func sendUnsupportedMediaTypeResponse(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusUnsupportedMediaType),
		http.StatusUnsupportedMediaType)
}

func sendUnauthorizedResponse(w http.ResponseWriter, requestID string,
	reason string) {
	err := sendJsonResponse(w, http.StatusUnauthorized, FailedRequestError{
		HttpCode: http.StatusUnauthorized,
		Message:  reason,
	})
	if err != nil {
		dstsLogger.Error("Failed to encode JSON response!",
			zap.String("Request ID: ", requestID),
			zap.Error(err),
		)
	}
}

func sendNotFoundErrorResponse(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusNotFound),
		http.StatusNotFound)
}

func sendServerBusyErrorResponse(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusTooManyRequests),
		http.StatusTooManyRequests)
}

// JSON encode and send the specified payload & the specified HTTP status code.
func sendJsonResponse(w http.ResponseWriter, statusCode int,
	payload interface{}) error {
	w.Header().Set(headerContentType, contentTypeJson)
	w.WriteHeader(statusCode)

	if payload != nil {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(payload)
		if err != nil {
			dstsLogger.Error("Failed to encode JSON response!",
				zap.Error(err),
			)
			sendInternalServerErrorResponse(w)
			return err
		}
	}

	return nil
}

func getRequestID(r *http.Request) string {
	requestID := r.Header.Get(headerRequestID)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	return requestID
}
