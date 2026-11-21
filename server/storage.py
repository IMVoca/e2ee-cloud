"""誠實伺服器：以資料夾模擬雲端（規格書第 5 節）。

伺服器只存放與回傳 JSON，不解讀任何內容。
客戶端只依賴這裡的公開方法，因此 MaliciousServer 繼承後可直接替換。

儲存配置（root 預設為 ./storage）：
    root/files/<file_id>.json   每個檔案一筆 FileRecord（dict）
    root/meta/<key>.json        使用者層級的資料，例如 KDF salt、V2 的清單 HMAC
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# 只允許安全字元，避免 file_id / key 被拿來做路徑穿越
_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.match(value):
        raise ValueError(f"不合法的 ID：{value!r}")
    return value


class HonestServer:
    def __init__(self, root: str | Path = "storage"):
        self.root = Path(root)
        self.files_dir = self.root / "files"
        self.meta_dir = self.root / "meta"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.meta_dir.mkdir(parents=True, exist_ok=True)

    # ---- 檔案 ----

    def put(self, record: dict) -> None:
        """新增或覆寫一筆檔案記錄。"""
        file_id = _check_id(record["file_id"])
        path = self.files_dir / f"{file_id}.json"
        path.write_text(json.dumps(record), encoding="utf-8")

    def get(self, file_id: str) -> dict:
        """取回一筆檔案記錄；不存在時拋 KeyError。"""
        path = self.files_dir / f"{_check_id(file_id)}.json"
        if not path.exists():
            raise KeyError(file_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def list(self) -> list[dict]:
        """回傳所有檔案記錄（依 file_id 排序，結果穩定）。"""
        return [
            json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(self.files_dir.glob("*.json"))
        ]

    # ---- 使用者層級資料 ----

    def put_meta(self, key: str, value: dict) -> None:
        path = self.meta_dir / f"{_check_id(key)}.json"
        path.write_text(json.dumps(value), encoding="utf-8")

    def get_meta(self, key: str) -> dict | None:
        """不存在時回傳 None（例如首次登入還沒有 salt）。"""
        path = self.meta_dir / f"{_check_id(key)}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
