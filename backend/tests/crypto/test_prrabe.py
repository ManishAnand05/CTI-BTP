"""Tests for the PR-RABE_P module (Member 3).

Run from repo root:  python -m pytest backend/tests/crypto -v

Scenario (mirrors proposal slide 19), L = 4 slots:
  slot 0  Org A   SECTOR:FINANCE, TRUST:HIGH
  slot 1  Org B   SECTOR:FINANCE, TRUST:HIGH
  slot 2  Org C   SECTOR:HEALTH,  TRUST:HIGH
  slot 3  Org D   SECTOR:FINANCE, TRUST:MEDIUM
"""

import json

import pytest
from charm.toolbox.pairinggroup import GT, GT as _GT, pair

from backend.crypto.prrabe import scheme
from backend.crypto.prrabe.hybrid import open_envelope, seal
from backend.crypto.prrabe.owner import AttributeGroups, DataOwner
from backend.crypto.prrabe.params import progression_free_set, setup

UNIVERSE = ["SECTOR:FINANCE", "SECTOR:HEALTH", "TRUST:HIGH", "TRUST:MEDIUM",
            "ORGTYPE:CERT", "ORGTYPE:SOC"]
ATTRS = {
    0: {"SECTOR:FINANCE", "TRUST:HIGH"},
    1: {"SECTOR:FINANCE", "TRUST:HIGH"},
    2: {"SECTOR:HEALTH", "TRUST:HIGH"},
    3: {"SECTOR:FINANCE", "TRUST:MEDIUM"},
}
POLICY = "SECTOR:FINANCE and TRUST:HIGH"
A, B, C, D = 0, 1, 2, 3


@pytest.fixture
def world():
    crs = setup(4)
    keys = [scheme.keygen(crs, i) for i in range(4)]
    mpk, hsk = scheme.aggregate(crs, [(keys[i][0], ATTRS[i]) for i in range(4)], UNIVERSE)
    owner = DataOwner(crs, mpk, AttributeGroups(crs.group, ATTRS))
    return crs, keys, mpk, hsk, owner


def dec(world, slot, ct):
    crs, keys, _, hsk, _ = world
    return scheme.decrypt(crs, hsk[slot], keys[slot][1], ct)


def forced_decrypt(crs, hsk, sk, ct, agks, claimed):
    """Adversarial decryption: skips every software check.

    agks:    row -> AGK value the attacker somehow obtained (e.g. leaked)
    claimed: row -> attribute the attacker pretends to hold
    Returns the computed m. Security means it is NOT the real message.
    """
    g = crs.group
    rows = sorted(agks)
    base = (ct.C1 / pair(ct.C2, hsk.B)) * pair(ct.C5, hsk.A) * pair(ct.C2, hsk.V_hat)
    acc = g.init(_GT, 1)
    for k in rows:
        acc *= pair(ct.C3p[k], hsk.A ** (1 / agks[k])) * pair(ct.C4[k], hsk.W_hat[claimed[k]])
    return base * acc * (pair(ct.C2, hsk.A) ** sk)


def recover_agk(crs, sk, ct, slot, k):
    g = crs.group
    return scheme.bytes_to_zr(g, scheme._xor(ct.hdr[k][slot], scheme._h(g, ct.C2 ** sk, k)))


# ------------------------------------------------------------- setup / keys

def test_index_set_properties():
    D_ = progression_free_set(20)
    S = set(D_)
    assert all(2 * x not in S for x in D_)                              # double-free
    assert all(i + j != 2 * k for i in D_ for j in D_ if i != j for k in D_)  # progression-free


def test_isvalid_accepts_honest_and_rejects_tampered_key(world):
    crs, keys, *_ = world
    pk = keys[0][0]
    assert scheme.is_valid(crs, 0, pk)
    assert not scheme.is_valid(crs, 1, pk)                       # wrong slot
    tampered = scheme.PublicKey(pk.slot, pk.T, pk.Q, dict(pk.V))
    tampered.V[1] = crs.A[1]                                     # not A_1^{r}
    assert not scheme.is_valid(crs, 0, tampered)


# ------------------------------------------------------------- correctness

def test_authorized_orgs_decrypt(world):
    crs, *_, owner = world
    m = crs.group.random(GT)
    ct = owner.encrypt("r1", POLICY, m)
    assert dec(world, A, ct) == m
    assert dec(world, B, ct) == m


@pytest.mark.parametrize("policy,allowed", [
    ("SECTOR:FINANCE or SECTOR:HEALTH", {A, B, C, D}),
    ("TRUST:HIGH", {A, B, C}),
    ("(SECTOR:FINANCE and TRUST:HIGH) or SECTOR:HEALTH", {A, B, C}),
    ("SECTOR:FINANCE and (TRUST:HIGH or TRUST:MEDIUM)", {A, B, D}),
])
def test_policy_matrix(world, policy, allowed):
    crs, *_, owner = world
    m = crs.group.random(GT)
    ct = owner.encrypt("p", policy, m)
    for slot in range(4):
        if slot in allowed:
            assert dec(world, slot, ct) == m
        else:
            with pytest.raises(scheme.DecryptionFailed):
                dec(world, slot, ct)


def test_offline_online_split(world):
    crs, _, mpk, _, owner = world
    m = crs.group.random(GT)
    off = scheme.encrypt_offline(crs, 4)          # done before the message exists
    ct = scheme.encrypt_online(crs, mpk, off, POLICY, m, owner.groups)
    assert dec(world, A, ct) == m


def test_ciphertext_hides_attribute_values(world):
    crs, *_, owner = world
    ct = owner.encrypt("r1", POLICY, crs.group.random(GT))
    public = json.dumps({"names": ct.names, "policy": ct.labelled_policy})
    assert "FINANCE" not in public and "HIGH" not in public
    assert ct.names == ["SECTOR", "TRUST"]


# ------------------------------------------------------------- unauthorized (cryptographic)

def test_wrong_sector_fails_even_with_leaked_agk(world):
    """Org C (HEALTH) gets both AGKs leaked and claims SECTOR:FINANCE. Math must refuse."""
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    ct = owner.encrypt("r1", POLICY, m)
    agks = {k: recover_agk(crs, keys[A][1], ct, A, k) for k in (0, 1)}   # leaked by Org A
    out = forced_decrypt(crs, hsk[C], keys[C][1], ct, agks,
                         {0: "SECTOR:FINANCE", 1: "TRUST:HIGH"})
    assert out != m


def test_collusion_does_not_combine_attributes(world):
    """Org C (has TRUST:HIGH, not FINANCE) and Org D (has FINANCE, not HIGH) collude."""
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    ct = owner.encrypt("r1", POLICY, m)
    agks = {k: recover_agk(crs, keys[A][1], ct, A, k) for k in (0, 1)}
    claimed = {0: "SECTOR:FINANCE", 1: "TRUST:HIGH"}
    for slot in (C, D):
        assert forced_decrypt(crs, hsk[slot], keys[slot][1], ct, agks, claimed) != m


def test_secret_key_needed(world):
    """Org A's public helper key with a wrong secret key does not decrypt."""
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    ct = owner.encrypt("r1", POLICY, m)
    with pytest.raises(scheme.DecryptionFailed):
        scheme.decrypt(crs, hsk[A], keys[B][1], ct)


# ------------------------------------------------------------- revocation (AGK)

def test_revocation_blocks_revoked_and_spares_others(world):
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    owner.encrypt("r1", POLICY, m)
    assert dec(world, B, owner.records["r1"].ct) == m

    res = owner.revoke(B, "TRUST:HIGH")                # trust High -> Medium
    assert res.records_reencrypted == 1 and res.new_agk_version == 2
    new_ct = owner.records["r1"].ct

    with pytest.raises(scheme.DecryptionFailed):
        dec(world, B, new_ct)
    assert dec(world, A, new_ct) == m                 # Org A: same key, still works


def test_revoked_org_cannot_reuse_old_agk(world):
    """B saved the old AGK before revocation; re-encryption with fresh s' defeats it."""
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    old = owner.encrypt("r1", POLICY, m)
    old_agks = {k: recover_agk(crs, keys[B][1], old, B, k) for k in (0, 1)}
    owner.revoke(B, "TRUST:HIGH")
    new = owner.records["r1"].ct
    out = forced_decrypt(crs, hsk[B], keys[B][1], new, old_agks,
                         {0: "SECTOR:FINANCE", 1: "TRUST:HIGH"})
    assert out != m


def test_scope_old_ciphertext_still_opens_for_revoked(world):
    """Documented scope: a copy B cached before revocation stays readable to B."""
    crs, *_, owner = world
    m = crs.group.random(GT)
    old = owner.encrypt("r1", POLICY, m)
    owner.revoke(B, "TRUST:HIGH")
    assert dec(world, B, old) == m


def test_known_limitation_agk_leak_after_revocation(world):
    """Documented limitation: if a current member leaks the NEW AGK to the revoked
    org, the revoked org (whose registered attributes are unchanged) can decrypt.
    This is inherent to group-key revocation; it is tested so it is never forgotten."""
    crs, keys, _, hsk, owner = world
    m = crs.group.random(GT)
    owner.encrypt("r1", POLICY, m)
    owner.revoke(B, "TRUST:HIGH")
    new = owner.records["r1"].ct
    leaked = {k: recover_agk(crs, keys[A][1], new, A, k) for k in (0, 1)}
    out = forced_decrypt(crs, hsk[B], keys[B][1], new, leaked,
                         {0: "SECTOR:FINANCE", 1: "TRUST:HIGH"})
    assert out == m


def test_revocation_only_touches_affected_records(world):
    crs, *_, owner = world
    owner.encrypt("fin", POLICY, crs.group.random(GT))
    owner.encrypt("health", "SECTOR:HEALTH", crs.group.random(GT))
    res = owner.revoke(B, "TRUST:HIGH")
    assert res.records_reencrypted == 1


# ------------------------------------------------------------- hybrid STIX payload

def test_hybrid_stix_roundtrip_and_revocation(world):
    crs, keys, _, hsk, owner = world
    stix = json.dumps({"type": "indicator", "spec_version": "2.1",
                       "pattern": "[ipv4-addr:value = '203.0.113.9']"}).encode()
    env = seal(owner, "rec-42", stix, POLICY)
    assert stix not in env.payload_ct
    ct = owner.records["rec-42"].ct
    assert open_envelope(crs, hsk[A], keys[A][1], ct, env) == stix
    owner.revoke(B, "TRUST:HIGH")
    ct = owner.records["rec-42"].ct
    with pytest.raises(scheme.DecryptionFailed):
        open_envelope(crs, hsk[B], keys[B][1], ct, env)
    assert open_envelope(crs, hsk[A], keys[A][1], ct, env) == stix


def test_new_records_after_revocation_are_blocked(world):
    """Primary guarantee: anything encrypted after revocation is unreadable to B."""
    crs, *_, owner = world
    owner.revoke(B, "TRUST:HIGH")
    m = crs.group.random(GT)
    ct = owner.encrypt("later", POLICY, m)
    with pytest.raises(scheme.DecryptionFailed):
        dec(world, B, ct)
    assert dec(world, A, ct) == m
