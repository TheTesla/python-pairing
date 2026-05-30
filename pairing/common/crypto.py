import os
import string
import random
import hmac as hmac_mod
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CHARSET = string.ascii_uppercase + string.digits


def generate_id(length=8):
    return ''.join(random.choices(CHARSET, k=length))


def generate_pin(length=6):
    return ''.join(random.choices(CHARSET, k=length))


def normalize_code(code):
    return code.strip().upper()


def parse_code(code):
    parts = normalize_code(code).split('-', 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("Format: ID-PIN (z.B. ABCD1234-123456)")
    return parts[0], parts[1]


def derive_confirm_key(spake_key):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"spake2-key-confirm",
    ).derive(spake_key)


def derive_session_key(spake_key):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"vpn-pairing-session-key",
    ).derive(spake_key)


def compute_hmac(key, client_id, client_msg, server_msg, role):
    data = role.encode() + client_id.encode() + client_msg + server_msg
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def constant_time_compare(a, b):
    return hmac_mod.compare_digest(a, b)
