CREATE TABLE customers (
    id   text PRIMARY KEY,
    name text NOT NULL
);

CREATE TABLE findings (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id text NOT NULL REFERENCES customers,
    title       text NOT NULL,
    detail      text            -- vault:v1:... ciphertext, or NULL
);

CREATE INDEX findings_customer_id_idx ON findings (customer_id);
