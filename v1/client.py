"""項目 3 客戶端 V1，有漏洞（負責：C）。

AES-CBC 加密、不做認證、檔名以明文存放。
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
        """下載並解密。"""
        raise NotImplementedError

    def list_files(self) -> list[tuple[str, str]]:
        """回傳 [(file_id, 檔名), ...]。"""
        raise NotImplementedError
