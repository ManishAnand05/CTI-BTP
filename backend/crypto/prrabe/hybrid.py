"""Hybrid encryption for CTI payloads (KEM-DEM).

PR-RABE encrypts a message m in GT, not arbitrary bytes. So:
  1. pick a fresh random m in GT (the KEM key),
  2. derive a 256-bit data key: DEK = HKDF-SHA256(serialize(m)),
  3. encrypt the STIX JSON with AES-256-GCM under DEK, AAD = record_id,
  4. protect m with PR-RABE under the access policy.
"""

import os
from dataclasses import dataclass

from charm.toolbox.pairinggroup import GT
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import scheme


def _dek(group, m):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"CTI-BTP PR-RABE DEK v1").derive(group.serialize(m))


@dataclass
class Envelope:
    record_id: str
    nonce: bytes
    payload_ct: bytes


def seal(owner, record_id, payload: bytes, policy: str) -> Envelope:
    group = owner.crs.group
    m = group.random(GT)
    owner.encrypt(record_id, policy, m)          # ABE part, kept by the DO / server
    nonce = os.urandom(12)
    ct = AESGCM(_dek(group, m)).encrypt(nonce, payload, record_id.encode())
    return Envelope(record_id, nonce, ct)


def open_envelope(crs, hsk, sk, abe_ct, env: Envelope) -> bytes:
    m = scheme.decrypt(crs, hsk, sk, abe_ct)
    return AESGCM(_dek(crs.group, m)).decrypt(env.nonce, env.payload_ct, env.record_id.encode())
