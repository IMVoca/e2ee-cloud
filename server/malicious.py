"""只修改儲存的 JSON；不接收密碼，也不持有任何金鑰。"""

import shutil

from common.record import b64d, b64e, new_file_id
from server.storage import HonestServer, _check_id


class MaliciousServer(HonestServer):
    def tamper_content(self, file_id: str, position: int,
                       original: bytes, replacement: bytes) -> None:
        """利用已知明文的 XOR 差值修改 IV 或密文。"""
        if position < 0 or len(original) != len(replacement):
            raise ValueError("位置必須非負，替換內容必須等長")
        record = self.get(file_id)
        delta = bytes(a ^ b for a, b in zip(original, replacement))
        if record["version"] == 1:
            block, offset = divmod(position, 16)
            if offset + len(delta) > 16:
                raise ValueError("CBC 攻擊不能跨越區塊")
            field = "nonce_or_iv" if block == 0 else "ciphertext"
            start = offset if block == 0 else (block - 1) * 16 + offset
            limit = len(b64d(record["ciphertext"]))
        elif record["version"] == 2:
            field, start = "ciphertext", position
            limit = len(b64d(record[field])) - 16  # 不修改 GCM tag。
        else:
            raise ValueError("不支援的記錄版本")
        if position + len(delta) > limit:
            raise ValueError("位置超出密文內容範圍")
        value = bytearray(b64d(record[field]))
        for i, difference in enumerate(delta):
            value[start + i] ^= difference
        record[field] = b64e(value)
        self.put(record)

    def inject_file(self, name: str, source_file_id: str | None = None) -> str:
        """複製既有密文；V1 可以任意指定明文檔名。"""
        if source_file_id is None:
            records = self.list()
            if not records:
                raise ValueError("沒有可複製的記錄")
            record = records[0]
        else:
            record = self.get(source_file_id)
        record["file_id"] = new_file_id()
        if record["version"] == 1:
            record["name"] = name
        self.put(record)
        return record["file_id"]

    def swap_names(self, file_id_a: str, file_id_b: str) -> None:
        """只對調名稱欄位，其餘欄位保持原值。"""
        a, b = self.get(file_id_a), self.get(file_id_b)
        a["name"], b["name"] = b["name"], a["name"]
        self.put(a)
        self.put(b)

    def snapshot(self, label: str) -> None:
        """整份保存 files 與 meta，覆寫同名快照。"""
        destination = self.root.resolve() / "snapshots" / _check_id(label)
        if destination.resolve() != destination:
            raise ValueError("快照路徑不可經由連結指向其他位置")
        if destination.exists():
            shutil.rmtree(destination)
        for source in (self.files_dir, self.meta_dir):
            shutil.copytree(source, destination / source.name)

    def rollback(self, label: str) -> None:
        """以快照取代 files 與 meta；不更動上傳順序紀錄。"""
        root = self.root.resolve()
        source = root / "snapshots" / _check_id(label)
        if not source.is_dir():
            raise KeyError(label)
        destinations = (self.files_dir, self.meta_dir)
        if source.resolve() != source or any(
            path.resolve() != root / path.name for path in destinations
        ):
            raise ValueError("回滾路徑不可經由連結指向其他位置")
        if not all((source / path.name).is_dir() for path in destinations):
            raise ValueError("快照缺少 files 或 meta 資料夾")
        for destination in destinations:
            shutil.rmtree(destination)
            shutil.copytree(source / destination.name, destination)
