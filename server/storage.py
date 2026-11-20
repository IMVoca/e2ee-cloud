"""項目 2 模擬雲端伺服器（負責：C）。

以資料夾儲存密文；提供上傳、下載、列出檔案。
"""


class HonestServer:
    def __init__(self, root: str = "storage"):
        """root：用來儲存密文的資料夾。"""
        self.root = root

    def upload(self, file_id: str, data: bytes) -> None:
        """上傳：儲存一份密文。"""
        raise NotImplementedError

    def download(self, file_id: str) -> bytes:
        """下載：取回一份密文。"""
        raise NotImplementedError

    def list_files(self) -> list[str]:
        """列出檔案。"""
        raise NotImplementedError
