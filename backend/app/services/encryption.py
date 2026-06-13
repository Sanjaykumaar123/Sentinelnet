"""
AES-256-GCM Encryption Service
- Per-message IV generation
- Auth tag included for tamper detection
- Ciphertext stored as: base64(iv + tag + ciphertext)
- Plaintext never persisted
"""
import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Derive a 32-byte AES key from the SECRET_KEY environment variable
def _get_message_key() -> bytes:
    raw = os.environ.get("MESSAGE_ENCRYPTION_KEY", "SENTINEL_DEFAULT_KEY_CHANGE_IN_PROD")
    return hashlib.sha256(raw.encode()).digest()

MESSAGE_KEY = _get_message_key()

def encrypt_message(plaintext: str) -> str:
    """
    Encrypt plaintext using AES-256-GCM.
    Returns base64-encoded payload: iv(12) + tag(16) + ciphertext
    """
    aesgcm = AESGCM(MESSAGE_KEY)
    iv = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    # AESGCM appends 16-byte tag to ciphertext automatically
    # Layout: iv (12 bytes) + ciphertext+tag
    payload = iv + ciphertext_with_tag
    return base64.b64encode(payload).decode("utf-8")

def decrypt_message(encrypted_payload: str) -> str:
    """
    Decrypt AES-256-GCM payload.
    Raises ValueError if tampered or invalid.
    """
    try:
        raw = base64.b64decode(encrypted_payload.encode("utf-8"))
        iv = raw[:12]
        ciphertext_with_tag = raw[12:]
        aesgcm = AESGCM(MESSAGE_KEY)
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def compute_integrity_hash(plaintext: str, sender_id: int, timestamp_str: str) -> str:
    """
    HMAC-SHA256 for message integrity verification.
    Prevents replay attacks when combined with nonce/timestamp.
    """
    msg = f"{sender_id}|{timestamp_str}|{plaintext}"
    return hmac.new(MESSAGE_KEY, msg.encode(), hashlib.sha256).hexdigest()

def verify_integrity(plaintext: str, sender_id: int, timestamp_str: str, provided_hash: str) -> bool:
    """Constant-time HMAC comparison to prevent timing attacks."""
    expected = compute_integrity_hash(plaintext, sender_id, timestamp_str)
    return hmac.compare_digest(expected, provided_hash)
