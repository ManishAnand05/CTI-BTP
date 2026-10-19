"""
Boundary between the policy engine and PR-RABE.

The policy engine decides WHAT must change (which attribute an
organization gains or loses, which record needs a new policy); a
PR-RABE backend does the cryptography (AGK rotation, header rebuild,
re-wrapping a record's data key).

MockPRRABE is a stand-in until the Charm-Crypto implementation exists.
It models attribute groups and their key versions faithfully enough to
measure revocation cost, and encrypts data with real AES-GCM, but the
data key is held in server memory instead of being ABE-encrypted. It
provides NO cryptographic access control.

To plug in the real scheme, implement the same methods and call
set_backend(YourBackend()) at startup.
"""

import base64
import json
import os
import threading

from backend.database import get_connection


class PRRABEBackend:
    """Interface the policy engine depends on."""

    def grant(self, organization_id, attribute):
        """Add an org to an attribute group. Returns {"group_version", ...}."""
        raise NotImplementedError

    def revoke(self, organization_id, attribute):
        """Remove an org from an attribute group and rotate its AGK."""
        raise NotImplementedError

    def protect_record(self, record_id, policy):
        """(Re-)wrap a record's data key under a policy. Returns {"key_version"}."""
        raise NotImplementedError

    def encrypt(self, plaintext, policy):
        """Hybrid-encrypt bytes under a policy. Returns a JSON-safe bundle."""
        raise NotImplementedError

    def decrypt(self, organization_id, bundle):
        """Return plaintext bytes, or raise PermissionError."""
        raise NotImplementedError


class MockPRRABE(PRRABEBackend):

    def __init__(self):
        self._lock = threading.Lock()
        self.groups = {}        # attribute -> {"members": set, "version": int}
        self.record_keys = {}   # record_id -> {"policy", "key_version"}
        self._escrow = {}       # bundle id -> data key (mock only)
        self._loaded = False

    def _group(self, attribute):
        return self.groups.setdefault(
            attribute, {"members": set(), "version": 1}
        )

    def _ensure_loaded(self):
        """Rebuild group membership from the policy engine's stored state."""
        if self._loaded:
            return
        self._loaded = True
        try:
            with get_connection() as connection:
                rows = connection.execute(
                    "SELECT organization_id, attributes FROM policy_org_state"
                ).fetchall()
        except Exception:
            return
        for row in rows:
            for attribute in json.loads(row["attributes"]):
                self._group(attribute)["members"].add(row["organization_id"])

    def grant(self, organization_id, attribute):
        with self._lock:
            self._ensure_loaded()
            group = self._group(attribute)
            group["members"].add(organization_id)
            # Joining needs only the new member's key; nobody else rekeys.
            return {"group_version": group["version"], "members_rekeyed": 0}

    def revoke(self, organization_id, attribute):
        with self._lock:
            self._ensure_loaded()
            group = self._group(attribute)
            group["members"].discard(organization_id)
            # Rotate this one AGK; only the remaining members of THIS group
            # get the new header. Other groups are untouched.
            group["version"] += 1
            return {
                "group_version": group["version"],
                "members_rekeyed": len(group["members"]),
            }

    def protect_record(self, record_id, policy):
        with self._lock:
            entry = self.record_keys.get(record_id)
            version = entry["key_version"] + 1 if entry else 1
            self.record_keys[record_id] = {
                "policy": policy,
                "key_version": version,
            }
            return {"key_version": version}

    def attributes_of(self, organization_id):
        with self._lock:
            self._ensure_loaded()
            return {
                attribute
                for attribute, group in self.groups.items()
                if organization_id in group["members"]
            }

    def encrypt(self, plaintext, policy):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        bundle_id = base64.urlsafe_b64encode(os.urandom(12)).decode()
        with self._lock:
            self._escrow[bundle_id] = key
        return {
            "id": bundle_id,
            "policy": policy,
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        }

    def decrypt(self, organization_id, bundle):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from backend.policy_engine import satisfies

        if not satisfies(self.attributes_of(organization_id), bundle["policy"]):
            raise PermissionError("Attributes do not satisfy the policy")
        with self._lock:
            key = self._escrow.get(bundle["id"])
        if key is None:
            raise PermissionError("Unknown ciphertext")
        return AESGCM(key).decrypt(
            base64.b64decode(bundle["nonce"]),
            base64.b64decode(bundle["ciphertext"]),
            None,
        )


_backend = MockPRRABE()


def get_backend():
    return _backend


def set_backend(backend):
    global _backend
    _backend = backend
