-- Drop the tombstoned devices table.
DROP TABLE IF EXISTS tombstoned_devices;

-- Drop the trigger to add tombstoned device table entries.
DROP FUNCTION IF EXISTS add_tombstoned_device();
DROP TRIGGER IF EXISTS add_tombstoned_device_trigger;
