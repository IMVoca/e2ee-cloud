"""驗收測試（負責：D）。

對應計畫書「三、驗收內容」：四個驗收項目，V1 與 V2 各一個測試。
對應功能完成後移除 skip。
"""

import pytest

pytestmark = pytest.mark.skip(reason="等待實作")


# ---- 正常上傳後下載 ----

def test_v1_upload_download():
    """V1：內容與原檔一致。"""


def test_v2_upload_download():
    """V2：內容與原檔一致。"""


# ---- 伺服器竄改檔案內容 ----

def test_v1_tamper_content():
    """V1：未察覺，接受錯誤內容。"""


def test_v2_tamper_content():
    """V2：偵測並拒絕。"""


# ---- 伺服器植入偽造檔案 ----

def test_v1_inject_file():
    """V1：清單出現偽造檔。"""


def test_v2_inject_file():
    """V2：偵測並拒絕。"""


# ---- 伺服器對調檔名 ----

def test_v1_swap_names():
    """V1：開啟 A 得到 B 的內容。"""


def test_v2_swap_names():
    """V2：偵測並拒絕。"""
