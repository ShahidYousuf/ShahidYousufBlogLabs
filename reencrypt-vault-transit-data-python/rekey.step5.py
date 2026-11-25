"""Re-key every customer: resumable, checked per customer, with a breaker."""

import sys

from mover import move_batch, ref
from vaultlab import VaultError, connect, key_name, new_vault, old_vault

MAX_CONSECUTIVE_FAILURES = 3


class CheckFailed(Exception):
    pass


MAX_ITEMS = 200
MAX_BYTES = 4 * 1024 * 1024


def plan_batches(rows):
    """Up to 200 rows or 4 MiB per Vault call; a bigger row goes alone."""
    batch, size = [], 0
    for row in rows:
        if batch and (
            len(batch) == MAX_ITEMS or size + len(row[1]) > MAX_BYTES
        ):
            yield batch
            batch, size = [], 0
        batch.append(row)
        size += len(row[1])
    if batch:
        yield batch


def check(conn, new, cid: str) -> int:
    """No rows left on the old key; the new key reads the biggest and 3 more."""
    left = conn.execute(
        "SELECT count(*) FROM findings WHERE customer_id = %s AND key_ref = %s",
        (cid, ref("old-vault", cid)),
    ).fetchone()[0]
    if left:
        raise CheckFailed(f"{left} rows still on the old key")
    sample = conn.execute(
        "(SELECT detail FROM findings WHERE key_ref = %(r)s"
        " ORDER BY length(detail) DESC LIMIT 1)"
        " UNION ALL"
        " (SELECT detail FROM findings WHERE key_ref = %(r)s"
        " ORDER BY random() LIMIT 3)",
        {"r": ref("new-vault", cid)},
    ).fetchall()
    for (detail,) in sample:
        new.decrypt(key_name(cid), [detail])  # raises VaultError if unreadable
    return len(sample)


def record(
    conn, cid: str, status: str, moved: int, error: str | None = None
) -> None:
    conn.execute(
        "INSERT INTO rekey_progress (customer_id, status, rows_moved, error)"
        " VALUES (%s, %s, %s, %s)"
        " ON CONFLICT (customer_id) DO UPDATE SET status = excluded.status,"
        " rows_moved = rekey_progress.rows_moved + excluded.rows_moved,"
        " error = excluded.error, updated_at = now()",
        (cid, status, moved, error),
    )
    conn.commit()


def main() -> None:
    old, new = old_vault(), new_vault()
    failures = 0
    with connect() as conn:
        todo = [
            r[0]
            for r in conn.execute(
                "SELECT c.id FROM customers c"
                " LEFT JOIN rekey_progress p ON p.customer_id = c.id"
                " WHERE p.status IS DISTINCT FROM 'done' ORDER BY c.id"
            )
        ]
        conn.commit()
        print(f"customers to go: {len(todo)}")
        for cid in todo:
            moved = skipped = 0
            try:
                rows = conn.execute(
                    "SELECT id, detail FROM findings"
                    " WHERE customer_id = %s AND key_ref = %s"
                    " ORDER BY id",
                    (cid, ref("old-vault", cid)),
                ).fetchall()
                conn.commit()
                for batch in plan_batches(rows):
                    m, s = move_batch(conn, old, new, cid, batch)
                    moved, skipped = moved + m, skipped + s
                sampled = check(conn, new, cid)
                conn.commit()
            except (VaultError, CheckFailed) as e:
                conn.rollback()
                record(conn, cid, "failed", moved, str(e))
                failures += 1
                print(f"{cid}: FAILED after moving {moved} rows: {e}")
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    sys.exit(
                        f"circuit breaker: {failures} customers failed in a row,"
                        " stopping"
                    )
                continue
            except KeyboardInterrupt:
                conn.rollback()
                sys.exit(
                    f"interrupted in {cid}: not marked done,"
                    f" {moved} rows already moved"
                )
            record(conn, cid, "done", moved)
            failures = 0
            print(
                f"{cid}: moved {moved}, skipped {skipped},"
                f" checked {sampled} on the new key"
            )


if __name__ == "__main__":
    main()
