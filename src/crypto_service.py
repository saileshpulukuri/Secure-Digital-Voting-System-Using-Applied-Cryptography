"""Cryptographic primitives: RSA-OAEP, RSA-PSS, SHA-256, bcrypt."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import bcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


RSA_KEY_SIZE = 2048
BCRYPT_ROUNDS = 12


def generate_rsa_keypair() -> tuple[bytes, bytes]:
    """Return (private_pem, public_pem) as UTF-8 PEM bytes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def integrity_hash_for_encrypted_vote(encrypted_vote_b64: str) -> str:
    raw = base64.b64decode(encrypted_vote_b64, validate=True)
    return sha256_hex(raw)


def _submission_message(encrypted_vote_b64: str, timestamp: str) -> bytes:
    return encrypted_vote_b64.encode("utf-8") + b"|" + timestamp.encode("utf-8")


def sign_submission(encrypted_vote_b64: str, timestamp: str, voter_private_pem: bytes) -> str:
    """RSA-PSS with SHA-256 over UTF-8 (encrypted_vote_b64 || '|' || timestamp)."""
    key = load_pem_private_key(voter_private_pem, password=None)
    msg = _submission_message(encrypted_vote_b64, timestamp)
    sig = key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def verify_submission_signature(
    encrypted_vote_b64: str, timestamp: str, signature_b64: str, voter_public_pem: bytes
) -> bool:
    try:
        key = load_pem_public_key(voter_public_pem)
        sig = base64.b64decode(signature_b64, validate=True)
        msg = _submission_message(encrypted_vote_b64, timestamp)
        key.verify(
            sig,
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def encrypt_vote_plaintext(plaintext: bytes, election_public_pem: bytes) -> str:
    key = load_pem_public_key(election_public_pem)
    ct = key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return base64.b64encode(ct).decode("ascii")


def decrypt_vote_ciphertext(encrypted_vote_b64: str, election_private_pem: bytes) -> bytes:
    key = load_pem_private_key(election_private_pem, password=None)
    raw = base64.b64decode(encrypted_vote_b64, validate=True)
    return key.decrypt(
        raw,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def parse_iso8601(ts: str) -> datetime:
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
