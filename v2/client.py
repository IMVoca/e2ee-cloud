"""V2：獨立子金鑰、AES-GCM 與 HMAC 清單驗證。"""

import json
import os
from contextlib import contextmanager

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.errors import IntegrityError
from common.kdf import derive_master_key, new_salt
from common.record import FileRecord, b64d, b64e, new_file_id
from server.storage import HonestServer

VERSION = 2


@contextmanager
def _integrity_checks():
    """將不可信資料的驗證與格式錯誤統一處理。"""
    try:
        yield
    except (InvalidTag, InvalidSignature, ValueError, KeyError,
            TypeError, AttributeError, IndexError) as exc:
        raise IntegrityError("檔案或清單驗證失敗") from exc


class Client:
    def __init__(self, server: HonestServer, password: str):
        self.server = server
        with _integrity_checks():
            salt_record = server.get_meta("salt")
            if salt_record is None:
                salt_record = {"salt": b64e(new_salt())}
                server.put_meta("salt", salt_record)
            self.K_master = derive_master_key(password, b64d(salt_record["salt"]))
        for purpose in ("wrap", "name", "manifest"):
            key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"e2ee-cloud v2 {purpose}".encode(),
            ).derive(self.K_master)
            setattr(self, "K_mac" if purpose == "manifest" else f"K_{purpose}", key)

    def _manifest_mac(self, entries: list) -> hmac.HMAC:
        canonical = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
        mac = hmac.HMAC(self.K_mac, hashes.SHA256())
        mac.update(canonical)
        return mac

    def _read_manifest(self) -> list:
        manifest = self.server.get_meta("manifest")
        if manifest is None:
            return []
        entries = manifest["entries"]
        self._manifest_mac(entries).verify(b64d(manifest["mac"]))
        if not isinstance(entries, list) or any(
            not isinstance(entry, list) or len(entry) != 2
            or not all(isinstance(value, str) for value in entry)
            for entry in entries
        ):
            raise IntegrityError("清單格式錯誤")
        if entries != sorted(entries) or len({e[0] for e in entries}) != len(entries):
            raise IntegrityError("清單排序或 ID 錯誤")
        return entries

    def _check_listing(self, entries: list) -> list[dict]:
        records = [r for r in self.server.list() if r["version"] == VERSION]
        actual = {(r["file_id"], r["name"]) for r in records}
        if actual != {tuple(e) for e in entries} or len(records) != len(entries):
            raise IntegrityError("伺服器清單與已認證清單不符")
        return records

    def _decrypt_name(self, file_id: str, name_field: str) -> bytes:
        encrypted = b64d(name_field)
        if len(encrypted) < 28:
            raise IntegrityError("加密檔名長度錯誤")
        name = AESGCM(self.K_name).decrypt(encrypted[:12], encrypted[12:], file_id.encode())
        name.decode("utf-8")  # 檔名必須是合法 UTF-8。
        return name

    def upload(self, name: str, data: bytes) -> str:
        """先驗證舊清單，再上傳並認證新清單。"""
        with _integrity_checks():
            entries = self._read_manifest()
            file_id = new_file_id()
            fid, name_utf8 = file_id.encode(), name.encode("utf-8")
            file_key = os.urandom(32)
            n_w, n_n, nonce = os.urandom(12), os.urandom(12), os.urandom(12)
            wrapped = n_w + AESGCM(self.K_wrap).encrypt(n_w, file_key, fid)
            name_field = b64e(n_n + AESGCM(self.K_name).encrypt(n_n, name_utf8, fid))
            ciphertext = AESGCM(file_key).encrypt(nonce, data, fid + b"\x00" + name_utf8)
            self.server.put(FileRecord(
                file_id, name_field, wrapped, nonce, ciphertext, VERSION
            ).to_dict())
            entries.append([file_id, name_field])
            entries.sort(key=lambda entry: entry[0])
            self.server.put_meta("manifest", {
                "entries": entries, "mac": b64e(self._manifest_mac(entries).finalize()),
            })
            return file_id

    def download(self, file_id: str) -> bytes:
        with _integrity_checks():
            entries = self._read_manifest()
            record = FileRecord.from_dict(self.server.get(file_id))
            if (record.version != VERSION or record.file_id != file_id
                    or [file_id, record.name] not in entries):
                raise IntegrityError("檔案不在已認證清單內")
            if len(record.wrapped_key) != 60 or len(record.nonce_or_iv) != 12:
                raise IntegrityError("金鑰或 nonce 長度錯誤")
            fid = file_id.encode()
            name_utf8 = self._decrypt_name(file_id, record.name)
            wrapped = record.wrapped_key
            file_key = AESGCM(self.K_wrap).decrypt(wrapped[:12], wrapped[12:], fid)
            return AESGCM(file_key).decrypt(
                record.nonce_or_iv, record.ciphertext, fid + b"\x00" + name_utf8
            )

    def list_files(self) -> list[tuple[str, str]]:
        """回傳 [(file_id, name), ...]；清單 HMAC 驗證失敗時拋 IntegrityError。"""
        with _integrity_checks():
            records = self._check_listing(self._read_manifest())
            return [(r["file_id"], self._decrypt_name(r["file_id"], r["name"]).decode("utf-8"))
                    for r in records]
