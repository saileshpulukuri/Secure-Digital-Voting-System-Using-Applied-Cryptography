"""Unit tests for cryptographic helpers (CDDR / proposal success criteria)."""

import base64
import json

import pytest

from src.crypto_service import (
    BCRYPT_ROUNDS,
    decrypt_vote_ciphertext,
    encrypt_vote_plaintext,
    generate_rsa_keypair,
    hash_password,
    integrity_hash_for_encrypted_vote,
    sign_submission,
    verify_password,
    verify_submission_signature,
)


def test_generate_rsa_keypair_pem_roundtrip():
    priv, pub = generate_rsa_keypair()
    assert b"BEGIN PRIVATE KEY" in priv
    assert b"BEGIN PUBLIC KEY" in pub
    priv2, pub2 = generate_rsa_keypair()
    assert priv != priv2


def test_bcrypt_hash_and_verify():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_bcrypt_cost_reasonable():
    h = hash_password("x" * 12)
    # bcrypt modular format: $2b$<cost>$...
    assert f"$2b${BCRYPT_ROUNDS}$" in h


def test_oaep_encrypt_decrypt_roundtrip():
    priv, pub = generate_rsa_keypair()
    msg = b'{"choice":"alice"}'
    ct_b64 = encrypt_vote_plaintext(msg, pub)
    out = decrypt_vote_ciphertext(ct_b64, priv)
    assert out == msg


def test_integrity_hash_sha256_of_ciphertext():
    priv, pub = generate_rsa_keypair()
    ct = encrypt_vote_plaintext(b"v1", pub)
    h1 = integrity_hash_for_encrypted_vote(ct)
    h2 = integrity_hash_for_encrypted_vote(ct)
    assert h1 == h2
    assert len(h1) == 64


def test_integrity_hash_changes_if_ciphertext_tampered():
    priv, pub = generate_rsa_keypair()
    ct = encrypt_vote_plaintext(b"v1", pub)
    raw = bytearray(base64.b64decode(ct))
    raw[0] ^= 0xFF
    ct2 = base64.b64encode(bytes(raw)).decode("ascii")
    assert integrity_hash_for_encrypted_vote(ct) != integrity_hash_for_encrypted_vote(ct2)


def test_sign_and_verify_submission():
    priv_v, pub_v = generate_rsa_keypair()
    _, pub_e = generate_rsa_keypair()
    plain = json.dumps({"choice": "B"}).encode()
    enc = encrypt_vote_plaintext(plain, pub_e)
    ts = "2026-04-04T12:00:00Z"
    sig = sign_submission(enc, ts, priv_v)
    assert verify_submission_signature(enc, ts, sig, pub_v)


def test_reject_wrong_signature():
    priv_v, pub_v = generate_rsa_keypair()
    _, pub_e = generate_rsa_keypair()
    enc = encrypt_vote_plaintext(b"x", pub_e)
    ts = "2026-04-04T12:00:00Z"
    _, pub_other = generate_rsa_keypair()
    sig = sign_submission(enc, ts, priv_v)
    assert not verify_submission_signature(enc, ts, sig, pub_other)


def test_reject_signature_on_tampered_timestamp():
    priv_v, pub_v = generate_rsa_keypair()
    _, pub_e = generate_rsa_keypair()
    enc = encrypt_vote_plaintext(b"x", pub_e)
    sig = sign_submission(enc, "2026-04-04T12:00:00Z", priv_v)
    assert not verify_submission_signature(enc, "2026-04-04T12:00:01Z", sig, pub_v)


def test_decrypt_fails_with_wrong_private_key():
    priv_a, pub_a = generate_rsa_keypair()
    priv_b, _pub_b = generate_rsa_keypair()
    ct = encrypt_vote_plaintext(b"secret", pub_a)
    with pytest.raises(Exception):
        decrypt_vote_ciphertext(ct, priv_b)
