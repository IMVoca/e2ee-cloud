"""項目 5 惡意伺服器（負責：D）。

模擬竄改檔案內容、植入偽造檔案、對調檔名；無法取得密碼或金鑰。
"""

from server.storage import HonestServer


class MaliciousServer(HonestServer):
    def tamper_content(self, file_id: str) -> None:
        """竄改檔案內容。"""
        raise NotImplementedError

    def inject_file(self) -> str:
        """植入偽造檔案，回傳偽造檔的 file_id。"""
        raise NotImplementedError

    def swap_names(self, file_id_a: str, file_id_b: str) -> None:
        """對調兩個檔案的檔名。"""
        raise NotImplementedError
