// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

// SigningKey - represents a token signing key used by the DSTS to sign
// device access tokens.
type SigningKey struct {
	// The ID of the signing key.
	KeyId string

	// The private key of the signing key.
	PrivateKey []byte

	// Whether the signing key is enabled.
	IsEnabled bool

	// Whether the signing key is the primary key currently used for
	// signing device access tokens.
	IsPrimary bool
}
