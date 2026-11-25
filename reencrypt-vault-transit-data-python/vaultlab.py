"""Shared helpers: one small Vault client over the HTTP API, and the database."""
import json
import os
from pathlib import Path

import psycopg
import requests

DSN = os.environ["DATABASE_URL"]
OLD_ADDR = os.environ["OLD_VAULT_ADDR"]
NEW_ADDR = os.environ["NEW_VAULT_ADDR"]
TOKENS = Path(".lab-tokens.json")  # lab only: never write real tokens to disk


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, name: str, addr: str, token: str):
        self.name = name
        self.addr = addr
        self.http = requests.Session()
        self.http.headers["X-Vault-Token"] = token

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        r = self.http.request(method, f"{self.addr}/v1/{path}", json=body, timeout=300)
        if r.status_code >= 400:
            try:
                body = r.json()
            except ValueError:
                body = {"errors": [r.text.strip()]}
            # Batch calls report per-item errors inside batch_results instead.
            results = (body.get("data") or {}).get("batch_results") or []
            errors = body.get("errors") or sorted({i["error"] for i in results if i.get("error")})
            raise VaultError(f"{self.name} {r.status_code}: {errors}")
        return r.json() if r.content else {}

    def decrypt(self, key: str, ciphertexts: list[str]) -> list[str]:
        """Ciphertexts in, base64 plaintexts out (never decoded here)."""
        out = self.call("POST", f"transit/decrypt/{key}",
                        {"batch_input": [{"ciphertext": c} for c in ciphertexts]})
        return [r["plaintext"] for r in out["data"]["batch_results"]]

    def encrypt(self, key: str, plaintexts_b64: list[str]) -> list[str]:
        out = self.call("POST", f"transit/encrypt/{key}",
                        {"batch_input": [{"plaintext": p} for p in plaintexts_b64]})
        return [r["ciphertext"] for r in out["data"]["batch_results"]]


def tokens() -> dict:
    return json.loads(TOKENS.read_text())


def old_vault() -> Vault:
    return Vault("old-vault", OLD_ADDR, tokens()["old_job"])


def new_vault() -> Vault:
    return Vault("new-vault", NEW_ADDR, tokens()["new_job"])


def connect(**kwargs) -> psycopg.Connection:
    return psycopg.connect(DSN, **kwargs)


def key_name(customer_id: str) -> str:
    return f"findings-{customer_id}"


def batches(rows: list, max_items: int = 200):
    """Split rows into lists of at most max_items."""
    for i in range(0, len(rows), max_items):
        yield rows[i:i + max_items]
