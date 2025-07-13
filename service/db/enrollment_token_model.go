// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import "time"

// EnrollmentToken - schema for the tenant enrollment token in the database.
type EnrollmentToken struct {
	// The identifier for the tenant to which this token belongs.
	TenantId string `json:"tenantid"`

	// The enrollment token.
	Token string `json:"token"`

	// Expiry timestamp for the enrollment token.
	TokenExpiresAt time.Time `json:"expires_at"`

	// Creation timestamp for the enrollment token.
	CreatedAt time.Time `json:"issued_at"`
}
