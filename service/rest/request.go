// package github.com/HPInc/krypton-dsts/service/rest
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package rest

const (
	// REST request headers and expected header values.
	headerContentType   = "Content-Type"
	headerRequestID     = "request_id"
	headerAuthorization = "Authorization"

	contentTypeFormUrlEncoded = "application/x-www-form-urlencoded"
	contentTypeJson           = "application/json"

	// Request parameters
	paramTenantID            = "tenant_id"
	paramDeviceID            = "device_id"
	paramAppID               = "app_id"
	paramEnrollmentToken     = "enrollment_token"
	paramClientAssertionType = "client_assertion_type"
	paramClientAssertion     = "client_assertion"
)
