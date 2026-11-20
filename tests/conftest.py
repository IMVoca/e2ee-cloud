import pytest

from server.storage import HonestServer


@pytest.fixture
def server(tmp_path):
    """每個測試一個乾淨的伺服器（存在暫存資料夾）。"""
    return HonestServer(str(tmp_path / "storage"))
