"""Data Owner (DO) side: attribute-group keys (AGK) and Revoke.

Paper Section 5.2, Encrypt (AGK assignment, groups I_x) and Revoke(i, x):
  1. I_x <- I_x \\ {i}
  2. sample a fresh AGK'_x
  3. re-encrypt with fresh randomness s' (and fresh v', s'_k)
  4. rebuild headers only for the remaining members of I_x

We follow the paper and re-encrypt with fresh randomness. Note on scope: a
copy the revoked organisation cached before revocation still opens for it, so
revocation protects (a) records it never retrieved and (b) all future records.

The paper's Revoke recomputes C1 = m * Z^{s'}, so the DO must retain m. Here
m is the random GT key that wraps the record's data key (see hybrid.py), held
in the DO's vault. Content an organisation already decrypted before revocation
is not protected (paper's stated scope).
"""

import time
from dataclasses import dataclass, field

from charm.toolbox.pairinggroup import ZR

from . import scheme
from .policy import parse_policy


class AttributeGroups:
    """AGK_x and member set I_x for every attribute x (DO-side secret state)."""

    def __init__(self, group, registrations):
        self.group = group
        self._members = {}
        self._agk = {}
        for slot, attrs in registrations.items():
            for x in attrs:
                self._members.setdefault(x, set()).add(slot)

    def members(self, x):
        return set(self._members.get(x, set()))

    def current(self, x):
        if x not in self._agk:
            self._agk[x] = (self.group.random(ZR), 1)
        return self._agk[x]

    def revoke(self, slot, x):
        if slot not in self._members.get(x, set()):
            raise ValueError(f"Slot {slot} is not in group {x}")
        self._members[x].discard(slot)
        _, version = self.current(x)
        self._agk[x] = (self.group.random(ZR), version + 1)
        return version + 1


@dataclass
class StoredRecord:
    record_id: str
    policy: str
    m: object               # DO vault: random GT key wrapped by PR-RABE
    ct: scheme.Ciphertext


@dataclass
class RevocationResult:
    slot: int
    attribute: str
    new_agk_version: int
    records_reencrypted: int
    elapsed_ms: float


class DataOwner:
    def __init__(self, crs, mpk, groups):
        self.crs, self.mpk, self.groups = crs, mpk, groups
        self.records = {}

    def encrypt(self, record_id, policy, m):
        ct = scheme.encrypt(self.crs, self.mpk, policy, m, self.groups)
        self.records[record_id] = StoredRecord(record_id, policy, m, ct)
        return ct

    def revoke(self, slot, x):
        """Revoke(i, x): rotate AGK_x and re-encrypt every record using x."""
        start = time.perf_counter()
        version = self.groups.revoke(slot, x)
        name, value = x.split(":", 1)
        count = 0
        for rec in self.records.values():
            rows = parse_policy(self.crs.group, rec.policy).rows
            if (name, value) in rows:
                rec.ct = scheme.encrypt(self.crs, self.mpk, rec.policy, rec.m, self.groups)
                count += 1
        elapsed = (time.perf_counter() - start) * 1000
        return RevocationResult(slot, x, version, count, elapsed)
