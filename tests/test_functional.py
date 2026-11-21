"""T1、T2、T9：功能與效能測試（規格見 docs/SPEC.md）。"""

import os

import pytest

from common.errors import IntegrityError
from common.record import FileRecord
from conftest import PASSWORD
from v1.client import Client as V1Client
from v2.client import Client as V2Client

CLIENTS = [pytest.param(V1Client, id="v1"), pytest.param(V2Client, id="v2")]
SIZES = [
    pytest.param(0, id="empty"),
    pytest.param(1024, id="1KB"),
    pytest.param(1024**2, id="1MB"),
    pytest.param(10 * 1024**2, id="10MB"),
]


# ---------- T1：誠實伺服器，上傳後下載內容完全相同 ----------


@pytest.mark.parametrize("Client", CLIENTS)
@pytest.mark.parametrize("size", SIZES)
def test_t1_roundtrip(server, Client, size):
    data = os.urandom(size)
    c = Client(server, PASSWORD)
    fid = c.upload("file.bin", data)
    assert c.download(fid) == data
    assert c.list_files() == [(fid, "file.bin")]


@pytest.mark.parametrize("Client", CLIENTS)
def test_t1_multiple_files(server, Client):
    c = Client(server, PASSWORD)
    files = {f"f{i}.txt": os.urandom(100 + i) for i in range(5)}
    ids = {name: c.upload(name, data) for name, data in files.items()}
    assert set(c.list_files()) == {(fid, name) for name, fid in ids.items()}
    for name, fid in ids.items():
        assert c.download(fid) == files[name]


@pytest.mark.parametrize("Client", CLIENTS)
def test_t1_new_session_same_password(server, Client):
    """換一個客戶端實例（模擬重新登入），salt 從伺服器取回，仍可解密。"""
    data = os.urandom(5000)
    fid = Client(server, PASSWORD).upload("a.bin", data)
    c2 = Client(server, PASSWORD)
    assert c2.download(fid) == data
    assert c2.list_files() == [(fid, "a.bin")]


@pytest.mark.parametrize("Client", CLIENTS)
def test_t1_unicode_filename(server, Client):
    c = Client(server, PASSWORD)
    fid = c.upload("期末報告 v2.pdf", b"hello")
    assert c.list_files() == [(fid, "期末報告 v2.pdf")]


@pytest.mark.parametrize("Client", CLIENTS)
def test_t1_honest_behaviour_of_malicious_server(evil, Client):
    """未呼叫攻擊方法時，MaliciousServer 行為與 HonestServer 相同。"""
    data = os.urandom(3000)
    c = Client(evil, PASSWORD)
    fid = c.upload("x.bin", data)
    assert c.download(fid) == data
    assert c.list_files() == [(fid, "x.bin")]


@pytest.mark.parametrize("Client", CLIENTS)
def test_server_never_sees_plaintext_content(server, Client):
    data = os.urandom(4096)
    fid = Client(server, PASSWORD).upload("secret.bin", data)
    stored = FileRecord.from_dict(server.get(fid))
    assert data[:64] not in stored.ciphertext
    assert len(stored.wrapped_key) > 32  # 檔案金鑰有被包裝，而非明文 32 bytes


def test_v2_server_never_sees_plaintext_name(server):
    fid = V2Client(server, PASSWORD).upload("secret-name.txt", b"x")
    assert "secret-name" not in server.get(fid)["name"]


# ---------- T2：密碼錯誤無法取得明文 ----------


@pytest.mark.parametrize("Client", CLIENTS)
def test_t2_wrong_password(server, Client):
    data = b"top secret " * 100
    fid = Client(server, PASSWORD).upload("s.txt", data)
    try:
        result = Client(server, "wrong password").download(fid)
    except Exception:
        return  # 拋例外 = 無法取得明文
    # V1 無認證：錯誤金鑰約 1/256 機率通過 PKCS7 unpad，但輸出必不等於原文
    assert result != data


def test_t2_v2_wrong_password_raises_integrity_error(server):
    fid = V2Client(server, PASSWORD).upload("s.txt", b"top secret")
    with pytest.raises(IntegrityError):
        V2Client(server, "wrong password").download(fid)
    with pytest.raises(IntegrityError):
        V2Client(server, "wrong password").list_files()


# ---------- T9：效能對照 ----------


@pytest.mark.parametrize("Client", CLIENTS)
def test_t9_performance(tmp_path, Client):
    from bench import benchmark

    result = benchmark(Client, tmp_path / "bench", size=10 * 1024**2, rounds=20)
    assert result["upload_avg_s"] > 0
    assert result["download_avg_s"] > 0
    print(f"\n[T9] {Client.__module__}: {result}")
