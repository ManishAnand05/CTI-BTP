"""Live demo of proposal slide 19: risk-driven AGK revocation with PR-RABE_P.

Run from repo root:  python -m backend.crypto.demo_slide19
"""

import json
import time

from backend.crypto.prrabe import scheme
from backend.crypto.prrabe.hybrid import open_envelope, seal
from backend.crypto.prrabe.owner import AttributeGroups, DataOwner
from backend.crypto.prrabe.params import setup

ORGS = {
    0: ("Org A (bank)",      {"SECTOR:FINANCE", "TRUST:HIGH"}),
    1: ("Org B (fintech)",   {"SECTOR:FINANCE", "TRUST:HIGH"}),
    2: ("Org C (hospital)",  {"SECTOR:HEALTH",  "TRUST:HIGH"}),
    3: ("Org D (insurer)",   {"SECTOR:FINANCE", "TRUST:MEDIUM"}),
}
UNIVERSE = ["SECTOR:FINANCE", "SECTOR:HEALTH", "TRUST:HIGH", "TRUST:MEDIUM"]
POLICY = "SECTOR:FINANCE and TRUST:HIGH"


def try_open(crs, hsk, keys, ct, env):
    for slot, (name, _) in ORGS.items():
        try:
            data = open_envelope(crs, hsk[slot], keys[slot][1], ct, env)
            print(f"   {name:18s} ACCESS   -> {json.loads(data)['name']}")
        except scheme.DecryptionFailed:
            print(f"   {name:18s} BLOCKED")


def main():
    print("1. Setup + each org generates its OWN key pair, KC aggregates")
    t = time.perf_counter()
    crs = setup(len(ORGS))
    keys = [scheme.keygen(crs, i) for i in ORGS]
    mpk, hsk = scheme.aggregate(crs, [(keys[i][0], ORGS[i][1]) for i in ORGS], UNIVERSE)
    owner = DataOwner(crs, mpk, AttributeGroups(crs.group, {i: a for i, (_, a) in ORGS.items()}))
    print(f"   done in {(time.perf_counter() - t) * 1000:.0f} ms\n")

    stix = json.dumps({"type": "campaign", "spec_version": "2.1", "name": "Campaign X",
                       "x_indicators": ["malware hash (Org A)", "C2 IP (Org B)"]}).encode()
    print(f"2. Risk analysis: Campaign X = Confidential, target Finance")
    print(f"   Access policy: {POLICY}")
    env = seal(owner, "campaign-x", stix, POLICY)
    ct = owner.records["campaign-x"].ct
    print(f"   Public ciphertext shows only attribute names: {ct.names}\n")
    try_open(crs, hsk, keys, ct, env)

    print("\n3. Weeks later: Org B misuse detected -> Trust High -> Medium (threshold crossed)")
    res = owner.revoke(1, "TRUST:HIGH")
    print(f"   AGK for TRUST:HIGH rotated to v{res.new_agk_version}, "
          f"{res.records_reencrypted} record re-encrypted in {res.elapsed_ms:.1f} ms")
    print("   No organisation's key was changed.\n")
    try_open(crs, hsk, keys, owner.records["campaign-x"].ct, env)


if __name__ == "__main__":
    main()
