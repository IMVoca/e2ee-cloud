"""V1：AES-CBC，刻意不驗證內容、檔名與清單。"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from common.kdf import derive_master_key, new_salt
from common.record import FileRecord, b64d, b64e, new_file_id
from server.storage import HonestServer

VERSION = 1


class Client:
    def __init__(self, server: HonestServer, password: str):
        self.server = server
        salt_record = server.get_meta("salt")
        if salt_record is None:
            salt_record = {"salt": b64e(new_salt())}
            server.put_meta("salt", salt_record)
        self.K_master = derive_master_key(password, b64d(salt_record["salt"]))

    def upload(self, name: str, data: bytes) -> str:
        """加密並上傳，回傳 file_id。"""
        file_id = new_file_id()
        file_key = os.urandom(32)
        iv_w, iv = os.urandom(16), os.urandom(16)
        wrapper = Cipher(algorithms.AES(self.K_master), modes.CBC(iv_w)).encryptor()
        wrapped_key = iv_w + wrapper.update(file_key) + wrapper.finalize()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(file_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        self.server.put(FileRecord(
            file_id, name, wrapped_key, iv, ciphertext, VERSION
        ).to_dict())
        return file_id

    def download(self, file_id: str) -> bytes:
        record = FileRecord.from_dict(self.server.get(file_id))
        unwrapper = Cipher(
            algorithms.AES(self.K_master), modes.CBC(record.wrapped_key[:16])
        ).decryptor()
        file_key = unwrapper.update(record.wrapped_key[16:]) + unwrapper.finalize()
        decryptor = Cipher(
            algorithms.AES(file_key), modes.CBC(record.nonce_or_iv)
        ).decryptor()
        padded = decryptor.update(record.ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def list_files(self) -> list[tuple[str, str]]:
        """回傳 [(file_id, name), ...]。"""
        return [(r["file_id"], r["name"]) for r in self.server.list()
                if r["version"] == VERSION]
