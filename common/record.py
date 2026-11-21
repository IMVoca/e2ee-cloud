"""伺服器上每個檔案的 JSON 記錄格式（規格書第 4 節）。

{ "file_id": "uuid", "name": "...", "wrapped_key": "base64",
  "nonce_or_iv": "base64", "ciphertext": "base64", "version": 1 }

- V1：name 為明文檔名。
- V2：name 為加密後的檔名（base64），其餘欄位意義由 V2 客戶端自行定義。
二進位欄位在 dataclass 內一律為 bytes，序列化成 JSON 時才轉 base64。
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def new_file_id() -> str:
    """由客戶端產生檔案 ID（不交給伺服器決定，V2 會把它放進 AAD）。"""
    return str(uuid.uuid4())


@dataclass
class FileRecord:
    file_id: str
    name: str
    wrapped_key: bytes
    nonce_or_iv: bytes
    ciphertext: bytes
    version: int

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "name": self.name,
            "wrapped_key": b64e(self.wrapped_key),
            "nonce_or_iv": b64e(self.nonce_or_iv),
            "ciphertext": b64e(self.ciphertext),
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> FileRecord:
        return cls(
            file_id=d["file_id"],
            name=d["name"],
            wrapped_key=b64d(d["wrapped_key"]),
            nonce_or_iv=b64d(d["nonce_or_iv"]),
            ciphertext=b64d(d["ciphertext"]),
            version=d["version"],
        )
