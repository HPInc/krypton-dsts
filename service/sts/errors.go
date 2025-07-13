// package github.com/HPInc/krypton-dsts/service/sts
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package sts

import "errors"

var (
	ErrUnsupportedSigningAlg          = errors.New("unexpected assertion signing method")
	ErrNoJwkSigningKey                = errors.New("assertion does not contain a JWK signing key")
	ErrInvalidDeviceOrTenantId        = errors.New("invalid device ID or tenant ID in device certificate")
	ErrInvalidDeviceCertificate       = errors.New("invalid device certificate provided")
	ErrMissingNonce                   = errors.New("failed to get nonce claim from client assertion")
	ErrInvalidAssertion               = errors.New("assertion is invalid")
	ErrAssertionExpired               = errors.New("assertion has expired")
	ErrAssertionNotValidYet           = errors.New("assertion is not yet valid")
	ErrInvalidDeviceChallenge         = errors.New("invalid nonce value in presented client assertion")
	ErrInvalidEnrollmentToken         = errors.New("invalid enrollment token provided")
	ErrExpiredEnrollmentToken         = errors.New("enrollment token has expired")
	ErrInvalidEnrollmentTokenLifetime = errors.New("enrollment token lifetime specified is invalid")
)
