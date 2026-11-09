import asyncio
import base64
import concurrent.futures
import gc
import hashlib
import json

import pytest

from aries_askar import AskarError, Key, KeyAlg, Store


MESSAGE = b"ML-DSA-44 wrapper test"
MLDSA_VARIANTS = [
    {
        "name": "mldsa44",
        "algorithm": KeyAlg.MLDSA44,
        "jwk_alg": "ML-DSA-44",
        "public_key_size": 1312,
        "secret_seed_size": 32,
        "signature_size": 2420,
        "public_key_hash": "2361ad0c41fc25431991ae53a92e559fa2df626e0f2a8aebb1216cde10f3391e",
    },
    {
        "name": "mldsa65",
        "algorithm": KeyAlg.MLDSA65,
        "jwk_alg": "ML-DSA-65",
        "public_key_size": 1952,
        "secret_seed_size": 32,
        "signature_size": 3309,
        "public_key_hash": "3cbeacd9f9fc167e91e0dc6531b7f75779b0133c87b0a212a0a2622ab2565fa2",
    },
    {
        "name": "mldsa87",
        "algorithm": KeyAlg.MLDSA87,
        "jwk_alg": "ML-DSA-87",
        "public_key_size": 2592,
        "secret_seed_size": 32,
        "signature_size": 4627,
        "public_key_hash": "2a4cb0c4aa69ee085f9cb2b0bf4c32dc46e164627aa44be18ffd013a30b8cc2b",
    },
]


@pytest.fixture(params=MLDSA_VARIANTS, ids=lambda params: params["name"])
def mldsa(request):
    return request.param


def _key_from_seed(algorithm: KeyAlg, seed: bytes = bytes(range(32))) -> Key:
    return Key.from_seed(algorithm, seed)


def _decode_base64url(value: str) -> bytes:
    assert isinstance(value, str)
    assert "+" not in value and "/" not in value and "=" not in value
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_mldsa_exports_expected_sizes_and_alg_id(mldsa):
    key = Key.generate(mldsa["algorithm"])

    assert KeyAlg.from_key_alg(mldsa["name"]) is mldsa["algorithm"]
    assert key.algorithm is mldsa["algorithm"]
    assert len(key.get_public_bytes()) == mldsa["public_key_size"]
    assert len(key.get_secret_bytes()) == mldsa["secret_seed_size"]
    assert len(key.sign_message(MESSAGE)) == mldsa["signature_size"]


def test_mldsa_seed_generation_is_deterministic(mldsa):
    first = _key_from_seed(mldsa["algorithm"])
    second = _key_from_seed(mldsa["algorithm"])

    assert first.get_public_bytes() == second.get_public_bytes()
    assert first.get_secret_bytes() == second.get_secret_bytes()
    assert hashlib.sha256(first.get_public_bytes()).hexdigest() == (
        mldsa["public_key_hash"]
    )
    assert first.verify_signature(MESSAGE, first.sign_message(MESSAGE))
    assert second.verify_signature(MESSAGE, second.sign_message(MESSAGE))


@pytest.mark.parametrize(
    "seed",
    [b"", b"x" * 31, b"x" * 33, b"short seed"],
    ids=["empty", "31-bytes", "33-bytes", "other-length"],
)
def test_mldsa_invalid_seed_length_is_rejected(mldsa, seed: bytes):
    with pytest.raises(AskarError):
        Key.from_secret_bytes(mldsa["algorithm"], seed)


def test_mldsa_random_key_generation_produces_distinct_keys(mldsa):
    first = Key.generate(mldsa["algorithm"])
    second = Key.generate(mldsa["algorithm"])

    assert first.get_public_bytes() != second.get_public_bytes()


@pytest.mark.parametrize("message", [b"", b"x", b"a" * (1024 * 1024)])
def test_mldsa_sign_and_verify_message_sizes(mldsa, message: bytes):
    key = Key.generate(mldsa["algorithm"])
    signature = key.sign_message(message)

    assert len(signature) == mldsa["signature_size"]
    assert key.verify_signature(message, signature)


def test_mldsa_verification_rejects_altered_inputs(mldsa):
    key = Key.generate(mldsa["algorithm"])
    other_key = Key.generate(mldsa["algorithm"])
    public_key = Key.from_public_bytes(mldsa["algorithm"], key.get_public_bytes())
    signature = key.sign_message(MESSAGE)

    assert not public_key.verify_signature(MESSAGE + b" altered", signature)
    assert not other_key.verify_signature(MESSAGE, signature)

    corrupted_signature = bytearray(signature)
    corrupted_signature[len(corrupted_signature) // 2] ^= 1
    try:
        valid = public_key.verify_signature(MESSAGE, bytes(corrupted_signature))
    except AskarError:
        valid = False
    assert not valid

    for malformed_signature in (signature[:-1], signature + b"\x00"):
        with pytest.raises(AskarError):
            public_key.verify_signature(MESSAGE, malformed_signature)


@pytest.mark.parametrize(
    "size_delta",
    [None, -1, 1],
    ids=["empty", "truncated", "too-long"],
)
def test_mldsa_rejects_invalid_public_key_lengths(mldsa, size_delta: int | None):
    size = 0 if size_delta is None else mldsa["public_key_size"] + size_delta
    public_key = b"\x00" * size
    with pytest.raises(AskarError):
        Key.from_public_bytes(mldsa["algorithm"], public_key)


def test_mldsa_public_and_private_jwk_round_trip(mldsa):
    key = _key_from_seed(mldsa["algorithm"])
    public = key.get_public_bytes()
    secret = key.get_secret_bytes()
    signature = key.sign_message(MESSAGE)

    public_jwk = json.loads(key.get_jwk_public())
    assert public_jwk["kty"] == "AKP"
    assert public_jwk["alg"] == mldsa["jwk_alg"]
    assert set(public_jwk) == {"kty", "alg", "pub"}
    assert _decode_base64url(public_jwk["pub"]) == public

    imported_public = Key.from_jwk(public_jwk)
    assert imported_public.get_public_bytes() == public
    assert imported_public.verify_signature(MESSAGE, signature)

    secret_jwk = json.loads(key.get_jwk_secret())
    assert secret_jwk["kty"] == "AKP"
    assert secret_jwk["alg"] == mldsa["jwk_alg"]
    assert set(secret_jwk) == {"kty", "alg", "pub", "priv"}
    assert _decode_base64url(secret_jwk["pub"]) == public
    assert _decode_base64url(secret_jwk["priv"]) == secret

    imported_secret = Key.from_jwk(secret_jwk)
    assert imported_secret.get_public_bytes() == public
    assert imported_secret.get_secret_bytes() == secret
    imported_signature = imported_secret.sign_message(MESSAGE)
    assert imported_secret.verify_signature(MESSAGE, imported_signature)


@pytest.mark.parametrize("secret", [b"", b"\x00" * 31, b"\x00" * 33])
def test_mldsa_rejects_invalid_secret_key_lengths(mldsa, secret: bytes):
    with pytest.raises(AskarError):
        Key.from_secret_bytes(mldsa["algorithm"], secret)


def test_mldsa_raw_key_import_round_trip(mldsa):
    key = _key_from_seed(mldsa["algorithm"])
    public = key.get_public_bytes()
    secret = key.get_secret_bytes()

    public_key = Key.from_public_bytes(mldsa["algorithm"], public)
    secret_key = Key.from_secret_bytes(mldsa["algorithm"], secret)
    signature = secret_key.sign_message(MESSAGE)

    assert public_key.get_public_bytes() == public
    assert secret_key.get_public_bytes() == public
    assert secret_key.get_secret_bytes() == secret
    assert public_key.verify_signature(MESSAGE, signature)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda jwk: jwk.pop("pub"),
        lambda jwk: jwk.update(kty="OKP"),
        lambda jwk: jwk.update(alg="not-ML-DSA"),
        lambda jwk: jwk.update(pub="%%%"),
        lambda jwk: jwk.update(pub="AA"),
        lambda jwk: jwk.update(pub=123),
    ],
    ids=[
        "missing-public",
        "wrong-kty",
        "wrong-alg",
        "invalid-base64url",
        "wrong-key-size",
        "wrong-field-type",
    ],
)
def test_mldsa_rejects_malformed_public_jwk(mldsa, mutate):
    jwk = json.loads(_key_from_seed(mldsa["algorithm"]).get_jwk_public())
    mutate(jwk)

    with pytest.raises((AskarError, TypeError, ValueError)):
        Key.from_jwk(jwk)


@pytest.mark.parametrize("private_value", ["%%%", "AA"])
def test_mldsa_rejects_malformed_private_jwk(mldsa, private_value: str):
    jwk = json.loads(_key_from_seed(mldsa["algorithm"]).get_jwk_secret())
    jwk["priv"] = private_value

    with pytest.raises((AskarError, TypeError, ValueError)):
        Key.from_jwk(jwk)


def test_mldsa_rejects_inconsistent_private_jwk(mldsa):
    jwk = json.loads(_key_from_seed(mldsa["algorithm"]).get_jwk_secret())
    other_public = json.loads(
        _key_from_seed(
            mldsa["algorithm"], bytes(reversed(range(32)))
        ).get_jwk_public()
    )["pub"]
    jwk["pub"] = other_public

    with pytest.raises(AskarError):
        Key.from_jwk(jwk)


def test_mldsa_signing_and_rejects_unknown_signature_type(mldsa):
    key = _key_from_seed(mldsa["algorithm"])

    signature = key.sign_message(MESSAGE)
    assert key.verify_signature(MESSAGE, signature)
    with pytest.raises(AskarError):
        key.sign_message(MESSAGE, "non-empty-context")

def test_mldsa_signing_is_hedged_not_reproducible(mldsa):
    key = _key_from_seed(mldsa["algorithm"])
    signatures = [key.sign_message(MESSAGE) for _ in range(5)]
    assert len(set(signatures)) == len(signatures)
    for signature in signatures:
        assert len(signature) == mldsa["signature_size"]
        assert key.verify_signature(MESSAGE, signature)

def test_mldsa_threaded_independent_operations(mldsa):
    def sign_and_verify(index: int) -> bool:
        key = Key.generate(mldsa["algorithm"])
        message = f"parallel message {index}".encode()
        signature = key.sign_message(message)
        return key.verify_signature(message, signature)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(sign_and_verify, range(8)))

    assert all(results)


def test_mldsa_repeated_key_lifecycle(mldsa):
    for _ in range(25):
        key = Key.generate(mldsa["algorithm"])
        signature = key.sign_message(MESSAGE)
        assert key.verify_signature(MESSAGE, signature)
        del key
    gc.collect()


def test_existing_ed25519_and_p256_signing_is_unchanged():
    for algorithm in (KeyAlg.ED25519, KeyAlg.P256):
        key = Key.generate(algorithm)
        signature = key.sign_message(MESSAGE)
        assert key.verify_signature(MESSAGE, signature)
        assert not key.verify_signature(MESSAGE + b" altered", signature)


def test_mldsa_store_memory_round_trip(mldsa):
    async def run():
        store_key = Store.generate_raw_key(b"mldsa store memory seed")
        store = await Store.provision("sqlite://:memory:", "raw", store_key)
        try:
            key = _key_from_seed(mldsa["algorithm"])
            async with store.session() as session:
                await session.insert_key(mldsa["name"], key)
                entry = await session.fetch_key(mldsa["name"])
                assert entry is not None
                assert entry.algorithm == mldsa["algorithm"].value
                signature = entry.key.sign_message(MESSAGE)
                assert key.verify_signature(MESSAGE, signature)
                await session.remove_key(mldsa["name"])
                assert await session.fetch_key(mldsa["name"]) is None
        finally:
            await store.close(remove=True)

    asyncio.run(run())


def test_mldsa_store_file_persists_encrypted_key(mldsa, tmp_path):
    async def run():
        uri = f"sqlite://{tmp_path / (mldsa['name'] + '.db')}"
        store_key = Store.generate_raw_key(b"mldsa store file seed")
        key = _key_from_seed(mldsa["algorithm"])
        store = await Store.provision(uri, "raw", store_key)
        async with store.session() as session:
            await session.insert_key(mldsa["name"], key)
        await store.close()

        reopened = await Store.open(uri, "raw", store_key)
        try:
            async with reopened.session() as session:
                entry = await session.fetch_key(mldsa["name"])
                assert entry is not None
                signature = entry.key.sign_message(MESSAGE)
                assert key.verify_signature(MESSAGE, signature)
            await reopened.close()
        finally:
            if reopened.handle:
                await reopened.close()

        with pytest.raises(AskarError):
            await Store.open(uri, "raw", Store.generate_raw_key(b"wrong store key"))
        await Store.remove(uri)

    asyncio.run(run())
