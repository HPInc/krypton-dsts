-- Create the table for tombstoned devices.
CREATE TABLE tombstoned_devices
(
  device_id VARCHAR(36) NOT NULL,
  tenant_id VARCHAR(36) NOT NULL,
  tombstoned_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(device_id,tenant_id)
);

CREATE OR REPLACE FUNCTION add_tombstoned_device()
RETURNS TRIGGER LANGUAGE plpgsql AS
$$
BEGIN
  INSERT INTO tombstoned_devices(device_id,tenant_id,tombstoned_at) 
    VALUES(OLD.device_id,OLD.tenant_id,now());
  RETURN OLD;
END;
$$;

-- Create a trigger to add a tombstoned device entry when the device is deleted.
CREATE TRIGGER add_tombstoned_device_trigger
  BEFORE DELETE on devices
  FOR EACH ROW EXECUTE PROCEDURE add_tombstoned_device();
