// package github.com/HPInc/krypton-dsts/service/db
// Author: Mahesh Unnikrishnan
// Component: Krypton Device Security Token Service
// (C) HP Development Company, LP
package db

// Database queries.
const (
	// Device lifecycle management queries
	queryInsertNewDevice = `INSERT INTO devices(device_id,tenant_id,is_enabled,is_lost,
		certificate_thumbprint,certificate_issued_at,certificate_expires_at,
		created_at,updated_at,service_id,hardware_hash) 
		VALUES($1,$2,$3,$4,$5,$6,$7,now(),now(),$8,$9)
		RETURNING created_at,updated_at,service_id`

	queryDeviceByID = `SELECT device_id,tenant_id,is_enabled,is_lost,certificate_thumbprint,
		certificate_issued_at,certificate_expires_at,
		COALESCE(previous_certificate_thumbprint,'') AS previous_certificate_thumbprint,
		created_at,updated_at,service_id, COALESCE(hardware_hash,'') AS hardware_hash FROM devices 
		WHERE devices.device_id=$1 and devices.tenant_id=$2`
	queryTombstonedDeviceByID = `SELECT device_id,tenant_id,tombstoned_at FROM tombstoned_devices 
		WHERE tombstoned_devices.device_id=$1 and tombstoned_devices.tenant_id=$2`
	queryListAllDevicesInTenant = `SELECT device_id,tenant_id,is_enabled,is_lost,
		certificate_thumbprint,certificate_issued_at,certificate_expires_at,created_at,
		updated_at,service_id,COALESCE(hardware_hash,'') AS hardware_hash FROM devices 
		WHERE devices.tenant_id=$1`
	queryListEnabledDevicesInTenant = `SELECT device_id,tenant_id,is_enabled,is_lost,
		certificate_thumbprint,certificate_issued_at,certificate_expires_at,created_at,
		updated_at,service_id,COALESCE(hardware_hash,'') AS hardware_hash FROM devices 
		WHERE devices.tenant_id=$1 and is_enabled=true`

	queryUpdateDeviceIsEnabled = `UPDATE devices SET updated_at=now(),is_enabled=$3 WHERE 
		devices.device_id=$1 and devices.tenant_id=$2`
	queryUpdateDeviceIsLost = `UPDATE devices SET updated_at=now(),is_lost=$3 WHERE 
		devices.device_id=$1 and devices.tenant_id=$2`
	queryUpdateDeviceCertificate = `UPDATE devices SET updated_at=now(),certificate_thumbprint=$3,
		certificate_issued_at=$4,certificate_expires_at=$5 WHERE devices.device_id=$1 and 
		devices.tenant_id=$2`
	queryDeletePreviousCertThumbprint = `UPDATE devices SET updated_at=now(),previous_certificate_thumbprint='' 
		WHERE devices.device_id=$1 and devices.tenant_id=$2`

	queryDeleteDeviceByID = `DELETE FROM devices WHERE devices.device_id=$1 and 
		devices.tenant_id=$2`

	// Management service queries
	queryGetManagementServices = `SELECT service_id,name,is_default FROM management_services`

	// Signing key management queries
	queryInsertNewSigningKey = `INSERT INTO signing_keys(key_id,private_key,is_enabled,
		is_primary) VALUES($1,$2,$3,$4) RETURNING key_id,is_enabled,is_primary`

	queryGetSigningKey = `SELECT key_id,private_key,is_enabled,is_primary FROM
		signing_keys WHERE signing_keys.key_id=$1`
	queryGetPrimarySigningKey = `SELECT key_id,private_key,is_enabled,is_primary FROM
	signing_keys WHERE signing_keys.is_primary=true and signing_keys.is_enabled=true`

	queryDeleteSigningKey = `DELETE FROM signing_keys WHERE signing_keys.key_id=$1`

	// Enrollment token management queries
	// #nosec G101
	queryInsertNewEnrollmentToken = `INSERT INTO enrollment_tokens(tenant_id,token,
		token_expires_at,created_at) VALUES($1,$2,$3,now()) 
		RETURNING tenant_id,token_expires_at,created_at`

	queryGetEnrollmentToken = `SELECT tenant_id,token,token_expires_at,created_at
		FROM enrollment_tokens WHERE tenant_id=$1`
	queryGetEnrollmentTokenInfo = `SELECT tenant_id,token,token_expires_at,created_at
		FROM enrollment_tokens WHERE token=$1`

	// #nosec G101
	queryDeleteEnrollmentToken = `DELETE FROM enrollment_tokens WHERE 
		enrollment_tokens.tenant_id=$1`

	// Registered app management queries
	queryInsertNewRegisteredApp = `INSERT INTO registered_apps(app_id,name,is_enabled,
		public_key_bytes,created_at,updated_at) VALUES($1,$2,$3,$4,now(),now()) 
		ON CONFLICT(app_id) DO UPDATE SET name=$2,is_enabled=$3,public_key_bytes=$4,
		updated_at=now() RETURNING created_at,updated_at`

	queryGetRegisteredApp = `SELECT app_id,name,is_enabled,public_key_bytes,
		created_at,updated_at FROM registered_apps WHERE registered_apps.app_id=$1`

	queryDeleteRegisteredApp = `DELETE FROM registered_apps WHERE 
		registered_apps.app_id=$1`
)
