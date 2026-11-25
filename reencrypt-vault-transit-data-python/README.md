# Move Vault-encrypted data to new keys

The lab for [How to Move Vault-Encrypted Data to New Keys Safely](https://shahidyousuf.dev/blog/reencrypt-vault-transit-data-python/). It runs two HashiCorp Vault servers (old and new), PostgreSQL full of per-customer encrypted fields, and a Python job that re-encrypts them under the new Vault's keys: resumably, per customer, sized for the largest field, and verified without storing plaintext.

The article explains each step and what its output means. This folder is the code.

Tested with Vault 2.2.2, PostgreSQL 18.7, Python 3.14.8, psycopg 3.3.9 and requests 2.34.2.

## Run it

You need Docker with Docker Compose.

```bash
docker compose up -d --wait db old-vault new-vault
docker compose build job
docker compose run --rm job python labvault.py init
docker compose run --rm job python labvault.py setup
docker compose run --rm job python seed.py
```

Then follow the article from Step 2.

## Files by step

| Step | Files |
|---|---|
| 1. Set up two Vaults and a database | `docker-compose.yml`, `new-vault.hcl`, `Dockerfile`, `requirements.txt`, `schema.sql`, `vaultlab.py`, `labvault.py`, `seed.py` |
| 2. Watch the naive loop fail | `rekey_naive.py` |
| 3. Record which key holds each row | `key_ref.sql`, `mover.py` |
| 4. Checkpoint per customer | `progress.sql`, `rekey.py` |
| 5. Size the job for your largest field | `new-vault.step5.hcl` (copy over `new-vault.hcl`), `rekey.step5.py` (byte-capped batches) |
| 6. Verify without storing plaintext | `verify.py`, `swap.sql` (plants a bug for the check to catch) |
| 7. Clean up | `labvault.py revoke`, then `docker compose down -v` |

## Before you copy anything

- The old Vault runs in dev mode: in memory, no TLS, a fixed root token. Restarting it loses every key.
- `labvault.py` writes the new Vault's unseal key and root token to `.new-vault-init.json`, and the job tokens to `.lab-tokens.json`. That's fine for a lab and never fine anywhere else. Both are gitignored here.
- `seed.py` prints a fake canary value on purpose; Step 7 hunts for it.

Clean up with `docker compose down -v`, then delete the two `.json` files.
