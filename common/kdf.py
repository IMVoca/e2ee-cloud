"""密碼 → 主金鑰（規格書第 4 節）。

V1 與 V2 共用同一套 KDF，確保對照實驗只差在「有沒有認證」。
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ITERATIONS = 600_000
SALT_LEN = 16
KEY_LEN = 32


def new_salt() -> bytes:
    """產生一組新的隨機 salt（註冊時使用一次，之後存在伺服器上）。"""
    return os.urandom(SALT_LEN)


def derive_master_key(password: str | bytes, salt: bytes) -> bytes:
    """以 PBKDF2-SHA256 由密碼推導 32 byte 主金鑰。"""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if len(salt) != SALT_LEN:
        raise ValueError(f"salt 必須是 {SALT_LEN} bytes，收到 {len(salt)}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password)
