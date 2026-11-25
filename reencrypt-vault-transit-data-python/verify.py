"""Prove the re-key without writing a single plaintext value anywhere."""

import base64
import hashlib
import hmac
import secrets
import sys

from mover import ref
from vaultlab import connect, key_name, new_vault, old_vault

# A random per-run key, held in memory and never written down.
CHECK_KEY = secrets.token_bytes(32)


def digest(plaintext_b64: str) -> bytes:
    return hmac.new(
        CHECK_KEY, base64.b64decode(plaintext_b64), hashlib.sha256
    ).digest()


old, new = old_vault(), new_vault()
with connect() as conn:
    counts = dict(
        conn.execute(
            "SELECT coalesce(split_part(key_ref, ':', 1), 'no detail'),"
            " count(*)"
            " FROM findings GROUP BY 1"
        ).fetchall()
    )
    before = conn.execute("SELECT count(*) FROM findings_before").fetchone()[0]
    print(
        f"rows: {counts}, total {sum(counts.values())}, before the run {before}"
    )

    # The 10 largest rows, which carry the size risk, plus 100 at random.
    sample = conn.execute(
        "(SELECT a.id, a.customer_id, b.detail, a.detail, a.key_ref"
        " FROM findings a"
        "  JOIN findings_before b USING (id) WHERE a.detail IS NOT NULL"
        "  ORDER BY length(a.detail) DESC LIMIT 10)"
        " UNION"
        " (SELECT a.id, a.customer_id, b.detail, a.detail, a.key_ref"
        " FROM findings a"
        "  JOIN findings_before b USING (id) WHERE a.detail IS NOT NULL"
        "  ORDER BY random() LIMIT 100)"
    ).fetchall()

mismatched = []
for row_id, cid, old_detail, new_detail, key_ref in sample:
    if key_ref != ref("new-vault", cid):
        mismatched.append(row_id)
        continue
    old_digest = digest(old.decrypt(key_name(cid), [old_detail])[0])
    new_digest = digest(new.decrypt(key_name(cid), [new_detail])[0])
    if not hmac.compare_digest(old_digest, new_digest):
        mismatched.append(row_id)

largest = max(len(s[3]) for s in sample)
print(
    f"sampled {len(sample)} rows (largest {largest:,} characters): "
    f"{len(sample) - len(mismatched)} match,"
    f" {len(mismatched)} differ {mismatched}"
)
ok = (
    counts.get("old-vault", 0) == 0
    and not mismatched
    and sum(counts.values()) == before
)
sys.exit(0 if ok else "verification FAILED")
