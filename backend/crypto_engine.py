import json
import base64
import hashlib
import os

# Simulated Revocation List
REVOKED_ORGS = set()

def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Pure Python Key Derivation Function (PBKDF2 style).
    Converts a text password into a 32-byte encryption key.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """
    Symmetric XOR cipher. XORing with the same key encrypts and decrypts.
    """
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_payload(data_dict, policy_attributes):
    """
    Simulates Attribute-Based Encryption using pure Python.
    The encryption key is derived from the policy (e.g., 'Finance').
    """
    # 1. Create the payload
    payload = {
        "data": data_dict,
        "policy": policy_attributes
    }
    raw_bytes = json.dumps(payload).encode('utf-8')

    # 2. Generate a random salt (for security)
    salt = os.urandom(16)

    # 3. Derive a key based on the required policy sector
    # If the policy requires "Finance", the key is derived from "Finance"
    secret_phrase = policy_attributes.get("sector", "All")
    key = _derive_key(secret_phrase, salt)

    # 4. Encrypt the data
    encrypted_bytes = _xor_cipher(raw_bytes, key)

    # 5. Bundle salt + encrypted data and Base64 encode it
    bundle = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "ciphertext": base64.b64encode(encrypted_bytes).decode('utf-8')
    }
    return base64.b64encode(json.dumps(bundle).encode('utf-8')).decode('utf-8')

def decrypt_payload(ciphertext_str, user_attributes):
    """
    Decrypts the payload by deriving the key from the user's attributes.
    """
    org_id = user_attributes.get("id")
    
    # 1. Check if the Organization is Revoked
    if org_id in REVOKED_ORGS:
        return {"success": False, "reason": "Access Revoked: Organization keys have been invalidated."}

    try:
        # 2. Unbundle the salt and ciphertext
        bundle_json = base64.b64decode(ciphertext_str).decode('utf-8')
        bundle = json.loads(bundle_json)
        
        salt = base64.b64decode(bundle["salt"])
        encrypted_bytes = base64.b64decode(bundle["ciphertext"])

        # 3. Derive the key using the USER'S sector
        # If the user is "Finance" but the policy was "Healthcare", the key will be wrong.
        user_phrase = user_attributes.get("sector", "Unknown")
        key = _derive_key(user_phrase, salt)

        # 4. Attempt to decrypt
        decrypted_bytes = _xor_cipher(encrypted_bytes, key)
        payload = json.loads(decrypted_bytes.decode('utf-8'))

    except Exception:
        return {"success": False, "reason": "Decryption failed: Invalid key or corrupted data (Attribute mismatch)."}

    policy = payload["policy"]
    data = payload["data"]

    # 5. Double check the policy (Trust score)
    required_trust = policy.get("min_trust", 0)
    user_trust = user_attributes.get("trust_score", 0)

    if user_trust < required_trust:
        return {"success": False, "reason": f"Access Denied: Requires trust score of {required_trust}, you have {user_trust}."}

    return {"success": True, "data": data}

def revoke_access(org_id):
    REVOKED_ORGS.add(org_id)
    return True

def restore_access(org_id):
    if org_id in REVOKED_ORGS:
        REVOKED_ORGS.remove(org_id)
    return True