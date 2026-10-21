# Crypto module (Member 3): PR-RABE encryption and revocation

## Setup (Linux or WSL2 Ubuntu; Charm does not build on native Windows)
```bash
sudo apt-get install -y libgmp-dev libssl-dev python3-dev flex bison m4 build-essential
wget https://crypto.stanford.edu/pbc/files/pbc-1.0.0.tar.gz && tar xzf pbc-1.0.0.tar.gz
cd pbc-1.0.0 && ./configure && make && sudo make install && sudo ldconfig && cd ..
pip install -r requirements-crypto.txt
```

## Run
```bash
python -m pytest backend/tests/crypto -v     # 19 tests
python -m backend.crypto.demo_slide19        # proposal slide 19, live
```

## Layout
| File | Contents |
|------|----------|
| prrabe/params.py | Group, index set, Setup -> CRS |
| prrabe/policy.py | Policy string -> LSSS (M, pi), name/value split, reconstruction |
| prrabe/scheme.py | KeyGen, IsValid, Aggregate, Encrypt (offline/online), Decrypt |
| prrabe/owner.py | AGK groups, DataOwner, Revoke |
| prrabe/hybrid.py | AES-256-GCM wrapping of STIX payloads |
| demo_slide19.py | End-to-end demo |

Not yet done (planned): serialization + DB storage, org-side keystore, Flask integration
with the policy engine, benchmarks. See docs/crypto/DEVIATIONS.md.
