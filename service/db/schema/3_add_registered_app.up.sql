-- Create the table for storing registered apps.
CREATE TABLE registered_apps
(
  app_id VARCHAR(36) NOT NULL,
  name VARCHAR(100),
  is_enabled BOOLEAN DEFAULT true,
  public_key_bytes BYTEA NOT NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(app_id)
);

-- Register the scheduler app.
INSERT INTO registered_apps
(
  app_id,name,is_enabled,public_key_bytes,created_at,updated_at
) VALUES(
  'bebc5cbf-acc0-431f-8c4e-c582dc2489e2',
  'Krypton scheduler',
  true,
  CAST('' AS BYTEA),
  now(),
  now()
);