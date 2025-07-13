// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

import "time"

// TombstonedDevice - schema for tombstoned devices in the database
type TombstonedDevice struct {
	// The unique immutable identifier assigned to the device. This is stamped
	// in the device certificate issued to the device.
	DeviceId string `json:"deviceid"`

	// The identifier for the tenant to which this device belongs.
	TenantId string `json:"tenantid"`

	// Tombstone timestamp for the device.
	TombstonedAt time.Time `json:"tombstoned_at"`
}
