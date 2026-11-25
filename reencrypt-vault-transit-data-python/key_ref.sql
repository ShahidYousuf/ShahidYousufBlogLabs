-- Which Vault cluster and which key can read each row.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS key_ref text;

UPDATE findings
   SET key_ref = 'old-vault:findings-' || customer_id
 WHERE detail IS NOT NULL AND key_ref IS NULL;

CREATE INDEX IF NOT EXISTS findings_customer_key_ref_idx
    ON findings (customer_id, key_ref);

-- Stand-in for the source database you are leaving: Step 5 verifies against it.
DROP TABLE IF EXISTS findings_before;
CREATE TABLE findings_before AS SELECT id, customer_id, detail FROM findings;
