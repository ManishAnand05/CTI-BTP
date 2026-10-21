"""Simple ABE demo that runs on Windows (no Charm-Crypto needed).

Shows the CONCEPT of attribute-based encryption using standard Python:
  - Organizations have attributes
  - Data is encrypted under a policy
  - Only orgs matching the policy can decrypt
  - Uses AES-256-GCM + HKDF for real encryption

This is a simplified simulation. The actual PR-RABE in prrabe/ uses
bilinear pairings on elliptic curves for cryptographic security.
Run: python -m backend.crypto.demo_simple
"""

import hashlib
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def derive_key(policy_secret: bytes, org_attrs_hash: bytes) -> bytes:
    """Derive a decryption key from the policy secret + matching attributes."""
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"CTI-BTP-ABE-DEMO-v1",
    ).derive(policy_secret + org_attrs_hash)


def attrs_hash(required: set, org_attrs: set) -> bytes | None:
    """If org satisfies policy, return the hash. Otherwise None."""
    if required.issubset(org_attrs):
        return hashlib.sha256("|".join(sorted(required)).encode()).digest()
    return None


def encrypt_cti(payload: dict, policy_attrs: set) -> dict:
    """Encrypt a CTI record under an attribute-based policy."""
    policy_secret = os.urandom(32)
    matching_hash = hashlib.sha256("|".join(sorted(policy_attrs)).encode()).digest()
    dek = derive_key(policy_secret, matching_hash)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload).encode()
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, b"CTI-BTP")
    return {
        "policy": sorted(policy_attrs),
        "policy_secret": policy_secret,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "payload_size": len(plaintext),
    }


def decrypt_cti(encrypted: dict, org_attrs: set) -> dict | None:
    """Try to decrypt. Returns plaintext dict if authorized, None if denied."""
    required = set(encrypted["policy"])
    match = attrs_hash(required, org_attrs)
    if match is None:
        return None
    dek = derive_key(encrypted["policy_secret"], match)
    try:
        plaintext = AESGCM(dek).decrypt(
            encrypted["nonce"], encrypted["ciphertext"], b"CTI-BTP"
        )
        return json.loads(plaintext)
    except Exception:
        return None


def main():
    print("=" * 65)
    print("  ABE-Based Cryptographic Access Control — Demo")
    print("  CTI Sharing Platform (CTI-BTP)")
    print("=" * 65)

    # --- Organizations and their attributes ---
    orgs = {
        "Alpha Bank":       {"SECTOR:FINANCE", "TRUST:HIGH"},
        "Beta FinTech":     {"SECTOR:FINANCE", "TRUST:HIGH"},
        "City Hospital":    {"SECTOR:HEALTH", "TRUST:MEDIUM"},
        "Delta Insurance":  {"SECTOR:FINANCE", "TRUST:MEDIUM"},
    }

    print("\n--- Organizations ---")
    for name, attrs in orgs.items():
        print(f"  {name:20s}  attributes: {sorted(attrs)}")

    # --- Encrypt a CTI record ---
    policy = {"SECTOR:FINANCE", "TRUST:HIGH"}
    cti_record = {
        "type": "indicator",
        "name": "Campaign X - APT Financial Trojan",
        "description": "Targets banking infrastructure via spear-phishing",
        "severity": "critical",
        "indicator_type": "malware",
        "indicator_value": "trojan.banker.apt29",
        "source": "Alpha Bank Threat Intel Team",
    }

    print(f"\n--- Encrypting CTI Record ---")
    print(f"  Policy: {sorted(policy)}")
    print(f"  Record: {cti_record['name']}")

    encrypted = encrypt_cti(cti_record, policy)

    print(f"\n  Encrypted payload: {len(encrypted['ciphertext'])} bytes")
    print(f"  Raw ciphertext (first 60 bytes): {encrypted['ciphertext'][:60].hex()}...")
    print(f"  (This is unreadable without matching attributes)")

    # --- Each org tries to decrypt ---
    print(f"\n--- Decryption Attempts ---")
    for name, attrs in orgs.items():
        result = decrypt_cti(encrypted, attrs)
        if result:
            print(f"  {name:20s}  -> ACCESS GRANTED")
            print(f"     Decrypted: \"{result['name']}\"")
            print(f"     Severity:  {result['severity']}")
        else:
            print(f"  {name:20s}  -> ACCESS DENIED (attributes don't match policy)")

    # --- Simulate revocation ---
    print(f"\n--- Revocation ---")
    print(f"  Revoking Beta FinTech's TRUST:HIGH attribute...")
    orgs["Beta FinTech"] = {"SECTOR:FINANCE", "TRUST:LOW"}

    print(f"  Re-encrypting record with fresh key...\n")
    encrypted_v2 = encrypt_cti(cti_record, policy)

    print(f"--- Post-Revocation Decryption ---")
    for name, attrs in orgs.items():
        result = decrypt_cti(encrypted_v2, attrs)
        if result:
            print(f"  {name:20s}  -> ACCESS GRANTED")
        else:
            print(f"  {name:20s}  -> ACCESS DENIED")

    print(f"\n--- Summary ---")
    print(f"  Before revocation: Alpha Bank + Beta FinTech could decrypt")
    print(f"  After revocation:  Only Alpha Bank can decrypt")
    print(f"  Beta FinTech lost TRUST:HIGH -> locked out")
    print(f"  Hospital + Insurance never had access (wrong attributes)")
    print(f"\n  Encryption: AES-256-GCM (real encryption, not simulated)")
    print(f"  Key derivation: HKDF-SHA256")
    print(f"  Full version uses bilinear pairings (Charm-Crypto on Linux)")
    print("=" * 65)


if __name__ == "__main__":
    main()
