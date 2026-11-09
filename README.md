# ML-DSA Tests for Aries Askar Python

This repository provides an integration test suite for the ML-DSA implementation in the [Aries Askar](https://github.com/Welhelha/askar) Python wrapper. It tests the ML-DSA-44, ML-DSA-65, and ML-DSA-87 variants, as well as regression coverage for Ed25519 and P-256 signatures.

> This repository is a test harness, not a standalone Python ML-DSA library. The Aries Askar code under test is fetched and compiled when pytest runs.

## Requirements

- Python 3.10 or later
- Git
- Rust 1.94 or later and Cargo
- A build toolchain compatible with the Rust dependencies

Each time a pytest session starts, `tests/conftest.py` fetches the pinned Aries Askar revision into `tests/.cache/askar` (cloning the repository if needed), checks out that revision, and runs a build with the `mldsa` feature enabled. Git and Cargo must be available, and network access is required for the fetch. Cargo may also need network access if dependencies are not already cached.

## Installation and Usage

From the repository root, create a virtual environment and install pytest:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest
```

Run the full test suite:

```bash
python -m pytest -q
```

To see the individual test cases:

```bash
python -m pytest -v tests/test_mldsa.py
```

The test setup builds the Rust wrapper when pytest starts. The first run may take longer than subsequent runs because Cargo can reuse previously built artifacts.

## Coverage

The tests cover, among other things:

- key and signature sizes, `KeyAlg` identifiers, and JWK `alg` values for all three ML-DSA variants;
- deterministic key generation from a seed and random key generation;
- signing and verifying messages of different sizes;
- rejection of invalid inputs and modified signatures;
- key import and export using `Key.from_public_bytes`, `Key.from_secret_bytes`, and `Key.from_jwk`; for ML-DSA, the exported secret is a 32-byte seed;
- AKP JWKs using `kty="AKP"`, the `ML-DSA-44`, `ML-DSA-65`, or `ML-DSA-87` `alg` value, and `pub` and (for private JWKs) `priv` fields;
- thread-based parallel operations and SQLite persistence;
- regression coverage for Ed25519 and P-256.
