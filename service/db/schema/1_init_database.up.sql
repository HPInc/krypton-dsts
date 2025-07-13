-- Initial schema for the device STS database.
-- Create the device management services table.
CREATE TABLE management_services
(
  service_id VARCHAR(36) NOT NULL,
  name VARCHAR(50) NOT NULL,
  is_default BOOLEAN DEFAULT false,
  PRIMARY KEY(service_id)
);

-- Create the devices table.
CREATE TABLE devices
(
  device_id VARCHAR(36) NOT NULL,
  tenant_id VARCHAR(36) NOT NULL,
  is_enabled BOOLEAN DEFAULT true,
  is_lost BOOLEAN DEFAULT false,
  certificate_thumbprint CHAR(64),
  certificate_issued_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  certificate_expires_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  previous_certificate_thumbprint VARCHAR(64),
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  service_id VARCHAR(36) NOT NULL,
  hardware_hash VARCHAR(50),
  PRIMARY KEY(device_id,tenant_id),
  CONSTRAINT fk_management_service
    FOREIGN KEY(service_id)
      REFERENCES management_services(service_id)
);
CREATE INDEX tenant_id_idx ON devices(tenant_id);
CREATE INDEX hardware_hash_idx ON devices(hardware_hash);

-- Replace all empty hardware hash fields with null.
CREATE OR REPLACE FUNCTION fix_hardware_hash()
RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
  NEW.hardware_hash := nullif(TRIM(NEW.hardware_hash), '');
  RETURN NEW;
END;
$$;

-- Create a trigger to replace empty hardware hash with null.
CREATE TRIGGER null_hardware_hash_trigger
  BEFORE INSERT OR UPDATE ON devices
  FOR EACH ROW EXECUTE PROCEDURE fix_hardware_hash();

-- Persist the old certificate thumbprint to support certificate rollovers
-- when the certificate thumbprint for a device object is renewed and updated.
CREATE OR REPLACE FUNCTION persist_previous_certificate_thumbprint()
RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
  IF(OLD.certificate_thumbprint != NEW.certificate_thumbprint) THEN
    NEW.previous_certificate_thumbprint = OLD.certificate_thumbprint;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_thumbprint_update_trigger
  BEFORE UPDATE ON devices
  FOR EACH ROW EXECUTE PROCEDURE persist_previous_certificate_thumbprint();

-- Create the enrollment tokens table.
CREATE TABLE enrollment_tokens
(
  tenant_id VARCHAR(36) NOT NULL,
  token VARCHAR(32) NOT NULL,
  token_expires_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(tenant_id)
);
CREATE INDEX enrollment_token_idx ON enrollment_tokens(token);

-- Add the registered device management services to the database.
INSERT INTO management_services(service_id, name, is_default) VALUES('none', 'Not managed', true);
INSERT INTO management_services(service_id, name, is_default) VALUES('hpconnect', 'HP Connect', false);
INSERT INTO management_services(service_id, name, is_default) VALUES('hpcem', 'HP Cloud Endpoint Manager', false);