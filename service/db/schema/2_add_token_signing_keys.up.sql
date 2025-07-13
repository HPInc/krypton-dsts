-- Create the signing keys table.
CREATE TABLE signing_keys
(
  key_id VARCHAR(100) NOT NULL,
  private_key BYTEA NOT NULL,
  is_enabled BOOLEAN DEFAULT true,
  is_primary BOOLEAN DEFAULT null,
  CONSTRAINT is_primary_true_or_null CHECK(is_primary),
  CONSTRAINT is_primary_only_one_true UNIQUE(is_primary),
  PRIMARY KEY(key_id)
);
