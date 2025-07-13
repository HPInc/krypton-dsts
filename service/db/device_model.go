// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import (
	"time"
)

// Device - schema for the devices table in the database.
type Device struct {
	// The unique immutable identifier assigned to the device. This is stamped
	// in the device certificate issued to the device.
	DeviceId string `json:"deviceid"`

	// The identifier for the tenant to which this device belongs.
	TenantId string `json:"tenantid"`

	// Specifies whether the device is enabled. Tokens will not be issued to
	// disabled devices.
	IsEnabled bool `json:"enabled"`

	// Specifies whether the device has been reported lost.
	IsLost bool `json:"is_lost"`

	// SHA256 hash of the device certificate used as a thumbprint to identify
	// the device certificate.
	CertificateThumbprint string `json:"cert_thumbprint"`

	// Timestamp at which the device certificate was issued.
	CertificateIssuedAt time.Time `json:"cert_issued_at"`

	// Expiry timestamp for the device certificate.
	CertificateExpiresAt time.Time `json:"cert_expires_at"`

	// Previous certificate thumbprint of the device. Present in the case of
	// device certificate rollovers.
	PreviousCertificateThumbprint string `json:"prev_cert_thumbprint"`

	// Creation and modification timestamps for the device object.
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// The device management service that manages this device.
	ServiceId string `json:"service_id"`

	// The hardware hash of the device.
	HardwareHash string `json:"hardware_hash,omitempty"`
}
