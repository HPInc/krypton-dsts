-- Register the HP Connect device management service app.
INSERT INTO registered_apps
(
  app_id,name,is_enabled,public_key_bytes,created_at,updated_at
) VALUES(
  '13d31cac-50cc-425a-a935-f871916848a6',
  'HP Connect Device Management Service',
  true,
  CAST('' AS BYTEA),
  now(),
  now()
);