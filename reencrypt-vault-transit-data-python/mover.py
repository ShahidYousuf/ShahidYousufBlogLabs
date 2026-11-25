"""Move one batch of rows from the old key to the new key, safely."""

import psycopg

from vaultlab import Vault, key_name


def ref(cluster: str, customer_id: str) -> str:
    return f"{cluster}:{key_name(customer_id)}"


def move_batch(
    conn: psycopg.Connection,
    old: Vault,
    new: Vault,
    customer_id: str,
    rows: list[tuple[int, str]],
) -> tuple[int, int]:
    """Re-encrypt rows [(id, old ciphertext)]. Returns (moved, skipped)."""
    key = key_name(customer_id)
    plaintexts = old.decrypt(
        key, [detail for _, detail in rows]
    )  # base64, never decoded
    ciphertexts = new.encrypt(key, plaintexts)
    del plaintexts  # drops our reference; Python can't wipe it
    moved = 0
    with conn.transaction(), conn.cursor() as cur:
        for (row_id, old_detail), new_detail in zip(rows, ciphertexts):
            # Compare-and-set: only a row still holding exactly
            # this old ciphertext changes.
            cur.execute(
                "UPDATE findings SET detail = %s, key_ref = %s"
                " WHERE id = %s AND key_ref = %s AND detail = %s",
                (
                    new_detail,
                    ref("new-vault", customer_id),
                    row_id,
                    ref("old-vault", customer_id),
                    old_detail,
                ),
            )
            moved += cur.rowcount
    return moved, len(rows) - moved
