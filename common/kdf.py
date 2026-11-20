"""項目 1 金鑰產生（負責：C）。

由密碼推導主金鑰（PBKDF2-SHA256），每個檔案另配隨機檔案金鑰。
"""


def derive_master_key(password: str, salt: bytes) -> bytes:
    """由密碼推導主金鑰（PBKDF2-SHA256）。"""
    raise NotImplementedError


def new_file_key() -> bytes:
    """為每個檔案產生一把隨機檔案金鑰。"""
    raise NotImplementedError
