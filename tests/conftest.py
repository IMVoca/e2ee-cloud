import pytest

from server.malicious import MaliciousServer
from server.storage import HonestServer

PASSWORD = "correct horse battery staple"


@pytest.fixture
def server(tmp_path):
    """每個測試一個乾淨的誠實伺服器（存在暫存資料夾）。"""
    return HonestServer(tmp_path / "storage")


@pytest.fixture
def evil(tmp_path):
    """惡意伺服器：攻擊方法被呼叫前行為與 HonestServer 相同。"""
    return MaliciousServer(tmp_path / "storage")
