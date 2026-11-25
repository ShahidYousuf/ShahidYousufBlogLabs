"""Play the application: encrypt findings under the old Vault and store them.

30 customers, one transit key each, a few thousand findings. Most details are
small; six are large, and one is about 20 MB. Re-running wipes the tables first.
"""

import base64
import random
import secrets

from vaultlab import OLD_ADDR, Vault, batches, connect, key_name, tokens

rng = random.Random(7)
# customer -> sizes in bytes of its large details, stored side by side
LARGE = {
    "c08": [900_000],
    "c14": [1_500_000],
    "c22": [3_000_000, 20_000_000, 3_000_000],
    "c27": [1_200_000],
}
CANARY = "CANARY-" + secrets.token_hex(8)


def small_detail() -> str:
    host = f"host-{rng.randint(1, 9999):04d}"
    words = " ".join(
        rng.choice(
            ["tls", "port", "header", "cookie", "cve", "banner", "redirect"]
        )
        for _ in range(rng.randint(5, 400))
    )
    return f"{host}: {words}"


def large_detail(size: int) -> str:
    # 81 bytes a line: 80 hex characters and a newline
    lines = [rng.randbytes(40).hex() for _ in range(size // 81 + 1)]
    return "\n".join(lines)[:size]


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def main() -> None:
    app = Vault("old-vault", OLD_ADDR, tokens()["old_app"])
    with connect() as conn:
        conn.execute("TRUNCATE findings, customers RESTART IDENTITY")
        total = nulls = 0
        for n in range(1, 31):
            cid = f"c{n:02d}"
            conn.execute(
                "INSERT INTO customers VALUES (%s, %s)", (cid, f"Customer {n}")
            )
            count = 150 if cid == "c22" else rng.randint(40, 180)
            details: list[str | None] = [small_detail() for _ in range(count)]
            if cid in LARGE:
                at = count * 2 // 3
                details[at:at] = [large_detail(size) for size in LARGE[cid]]
            if cid == "c03":
                details[10] = CANARY
            for i in rng.sample(range(len(details)), 1 if n % 5 == 0 else 0):
                details[i] = None  # a finding with no detail: never encrypted
            stored: list[str | None] = []
            for chunk in batches(details, 50):
                plain = [d for d in chunk if d is not None]
                cipher = iter(
                    app.encrypt(key_name(cid), [b64(d) for d in plain])
                )
                stored += [
                    next(cipher) if d is not None else None for d in chunk
                ]
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO findings (customer_id, title, detail)"
                    " VALUES (%s, %s, %s)",
                    [
                        (cid, f"Finding {i + 1}", s)
                        for i, s in enumerate(stored)
                    ],
                )
            total += len(stored)
            nulls += stored.count(None)
    print(f"seeded 30 customers, {total} findings ({nulls} with no detail)")
    print(f"canary: {CANARY}  base64: {b64(CANARY)}")


if __name__ == "__main__":
    main()
