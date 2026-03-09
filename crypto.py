"""
Криптографические функции для сквозного шифрования (E2E).
Клиент генерирует ключи, серver только передаёт ciphertext.
"""

import os
import base64
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Размер ключа ChaCha20-Poly1305: 32 байта
KEY_SIZE = 32
NONCE_SIZE = 12  # 96 бит
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100_000

def generate_room_key(room_secret: str, password: str = None) -> bytes:
    """
    Генерирует криптографический ключ комнаты.
    Если задан пароль, используется PBKDF2 для вывода ключа из пароля + room_secret.
    Иначе используется直接用 room_secret (должно быть случайной строкой из 32 байт).
    """
    if password:
        salt = get_random_bytes(SALT_SIZE)
        # salt передаётся в комнате отдельно (base64)
        key = PBKDF2(password, room_secret + salt.hex(), dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
        return key, salt
    else:
        # room_secret should be 32 random bytes encoded as string (e.g., base64)
        try:
            key = base64.urlsafe_b64decode(room_secret)
            if len(key) != KEY_SIZE:
                raise ValueError("room_secret must decode to 32 bytes")
            return key, None
        except Exception:
            raise ValueError("Invalid room_secret format")

def encrypt_message(plaintext: str, key: bytes) -> str:
    """
    Шифрует сообщение. Возвращает base64(nonce + ciphertext + tag).
    """
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    nonce = cipher.nonce
    payload = nonce + ciphertext + tag
    return base64.urlsafe_b64encode(payload).decode('utf-8')

def decrypt_message(token: str, key: bytes) -> str:
    """
    Расшифровывает сообщение. token = base64(nonce+ciphertext+tag).
    """
    try:
        data = base64.urlsafe_b64decode(token.encode('utf-8'))
        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:-16]
        tag = data[-16:]
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def generate_room_secret() -> str:
    """Генерирует случайный 32-байтовый секрет комнаты (base64)."""
    return base64.urlsafe_b64encode(get_random_bytes(KEY_SIZE)).decode('utf-8')

def generate_user_id() -> str:
    """Короткий идентификатор пользователя (base64 8 байт)."""
    return base64.urlsafe_b64encode(get_random_bytes(8)).decode('utf-8')[:11]
