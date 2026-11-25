CREATE TABLE IF NOT EXISTS rekey_progress (
    customer_id text PRIMARY KEY REFERENCES customers,
    status      text NOT NULL CHECK (status IN ('done', 'failed')),
    rows_moved  integer NOT NULL DEFAULT 0,
    error       text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
