"""The obvious re-key: decrypt on the old Vault, encrypt on the new, update."""

from vaultlab import batches, connect, key_name, new_vault, old_vault

old, new = old_vault(), new_vault()

with connect(autocommit=True) as conn:
    customers = [
        r[0] for r in conn.execute("SELECT id FROM customers ORDER BY id")
    ]
    for cid in customers:
        rows = conn.execute(
            "SELECT id, detail FROM findings"
            " WHERE customer_id = %s AND detail IS NOT NULL ORDER BY id",
            (cid,),
        ).fetchall()
        for chunk in batches(rows, 50):
            plain = old.decrypt(key_name(cid), [detail for _, detail in chunk])
            cipher = new.encrypt(key_name(cid), plain)
            for (row_id, _), c in zip(chunk, cipher):
                conn.execute(
                    "UPDATE findings SET detail = %s WHERE id = %s",
                    (c, row_id),
                )
        print(f"{cid}: {len(rows)} rows re-encrypted")
