"""Lab admin for both Vaults: init, unseal, setup, revoke.

Usage: python labvault.py init | unseal | setup | revoke
"""
import json
import sys
from pathlib import Path

import requests

from vaultlab import NEW_ADDR, OLD_ADDR, TOKENS, Vault, key_name

INIT_FILE = Path(".new-vault-init.json")  # lab only: unseal key and root token
CUSTOMERS = [f"c{n:02d}" for n in range(1, 31)]

JOB_POLICY_OLD = """
path "transit/decrypt/findings-*" { capabilities = ["update"] }
"""
JOB_POLICY_NEW = """
path "transit/encrypt/findings-*" { capabilities = ["update"] }
path "transit/decrypt/findings-*" { capabilities = ["update"] }
"""


def roots() -> tuple[Vault, Vault]:
    init = json.loads(INIT_FILE.read_text())
    return (Vault("old-vault", OLD_ADDR, "old-root"),
            Vault("new-vault", NEW_ADDR, init["root_token"]))


def init() -> None:
    r = requests.put(f"{NEW_ADDR}/v1/sys/init",
                     json={"secret_shares": 1, "secret_threshold": 1}, timeout=30)
    r.raise_for_status()
    INIT_FILE.write_text(json.dumps(r.json()))
    print("new-vault initialized")
    unseal()


def unseal() -> None:
    key = json.loads(INIT_FILE.read_text())["keys_base64"][0]
    r = requests.put(f"{NEW_ADDR}/v1/sys/unseal", json={"key": key}, timeout=30)
    r.raise_for_status()
    print(f"new-vault sealed: {r.json()['sealed']}")


def setup() -> None:
    tokens = {}
    for vault, policy, role in zip(roots(), (JOB_POLICY_OLD, JOB_POLICY_NEW), ("old", "new")):
        vault.call("POST", "sys/mounts/transit", {"type": "transit"})
        vault.call("PUT", "sys/audit/file",
                   {"type": "file", "options": {"file_path": "/vault/logs/audit.log"}})
        for customer in CUSTOMERS:
            vault.call("POST", f"transit/keys/{key_name(customer)}")
        vault.call("PUT", "sys/policies/acl/rekey-job", {"policy": policy})
        token = vault.call("POST", "auth/token/create",
                           {"policies": ["rekey-job"], "ttl": "8h", "no_default_policy": True})
        tokens[f"{role}_job"] = token["auth"]["client_token"]
        print(f"{vault.name}: transit on, audit on, {len(CUSTOMERS)} keys, job token issued")
    # The seed script plays the application, so it gets an encrypt token on the old Vault.
    old, _ = roots()
    old.call("PUT", "sys/policies/acl/app",
             {"policy": 'path "transit/encrypt/findings-*" { capabilities = ["update"] }'})
    app = old.call("POST", "auth/token/create", {"policies": ["app"], "ttl": "8h"})
    tokens["old_app"] = app["auth"]["client_token"]
    TOKENS.write_text(json.dumps(tokens))


def revoke() -> None:
    old, new = roots()
    issued = json.loads(TOKENS.read_text())
    for name, vault in (("old_job", old), ("new_job", new), ("old_app", old)):
        vault.call("POST", "auth/token/revoke", {"token": issued[name]})
        print(f"revoked {name} on {vault.name}")
    TOKENS.unlink()


if __name__ == "__main__":
    {"init": init, "unseal": unseal, "setup": setup, "revoke": revoke}[sys.argv[1]]()
