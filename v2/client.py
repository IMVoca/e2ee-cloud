"""項目 4 客戶端 V2，修正版（負責：C）。

AES-GCM 認證加密，檔名綁定驗證資料，檔案清單加 HMAC。
伺服器竄改內容、植入偽造檔案、對調檔名時，都要偵測並拒絕。
"""

from server.storage import HonestServer


class Client:
    def __init__(self, server: HonestServer, password: str):
        self.server = server
        raise NotImplementedError

    def upload(self, name: str, data: bytes) -> str:
        """加密並上傳，回傳 file_id。"""
        raise NotImplementedError

    def download(self, file_id: str) -> bytes:
        """下載、驗證並解密；驗證失敗時拒絕。"""
        raise NotImplementedError

    def list_files(self) -> list[tuple[str, str]]:
        """回傳 [(file_id, 檔名), ...]；清單 HMAC 驗證失敗時拒絕。"""
        raise NotImplementedError
