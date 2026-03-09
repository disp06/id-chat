"""
Криптография: AES-GCM (256-bit) для E2E шифрования.
Клиент использует Web Crypto API (AES-GCM), сервер — PyCryptodome.
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_SIZE = 32      # 256-bit key
NONCE_SIZE = 12    # 96-bit nonce for GCM
TAG_SIZE = 16      # 128-bit tag

def generate_room_secret() -> str:
    """Случайный 32-байтовый ключ в base64url."""
    return base64.urlsafe_b64encode(get_random_bytes(KEY_SIZE)).decode('utf-8')

def generate_user_id() -> str:
    """Короткий ID пользователя (base64url, ~11 chars)."""
    return base64.urlsafe_b64encode(get_random_bytes(8)).decode('utf-8')[:11]

def import_secret(secret_b64url: str) -> bytes:
    """Декодировать base64url секрет в 32-байтовый ключ."""
    b64 = secret_b64url.replace('-', '+').replace('_', '/')
    missing_padding = 4 - (len(b64) % 4)
    if missing_padding != 4:
        b64 += '=' * missing_padding
    raw = base64.b64decode(b64)
    if len(raw) != KEY_SIZE:
        raise ValueError("Invalid secret length (expected 32 bytes)")
    return raw

def encrypt_message(plaintext: str, key: bytes) -> str:
    """Шифрует строку, возвращает base64url(nonce + ciphertext + tag)."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    payload = cipher.nonce + ciphertext + tag
    b64 = base64.urlsafe_b64encode(payload).decode('utf-8')
    return b64.replace('+', '-').replace('/', '_').rstrip('=')

def decrypt_message(token_b64url: str, key: bytes) -> str:
    """Расшифровывает token (base64url), возвращает исходную строку."""
    # Восстановить padding
    b64 = token_b64url.replace('-', '+').replace('_', '/')
    missing_padding = 4 - (len(b64) % 4)
    if missing_padding != 4:
        b64 += '=' * missing_padding
    data = base64.b64decode(b64)
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext too short")
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:-TAG_SIZE]
    tag = data[-TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')
