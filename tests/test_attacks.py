"""T3–T8：惡意伺服器攻擊測試（規格見 docs/SPEC.md 第 3 節）。

V1 測試斷言「攻擊成功」，V2 測試斷言「偵測並拋出 IntegrityError」。
"""

import pytest

from common.errors import IntegrityError
from conftest import PASSWORD
from v1.client import Client as V1Client
from v2.client import Client as V2Client

# 第 0 區塊內的已知明文："Transfer $0100 t"，金額位於 index 10..13
TRANSFER = b"Transfer $0100 to Alice. Approved by Bob."
POS = TRANSFER.index(b"0100")

# 三個完整區塊；金額位於第 1 區塊 index 24..27
BLOCKY = b"HEADER-BLOCK-16B" + b"Amount: 0100 USD" + b" end of message."
POS_BLOCK1 = BLOCKY.index(b"0100")


def _by_name(client):
    return {name: fid for fid, name in client.list_files()}


# ---------- 攻擊 1：竄改內容 ----------


def test_t3_v1_tamper_content_first_block(evil):
    """T3：V1 接受被精準竄改的內容（$0100 → $9100），其餘內容完全不變。"""
    c = V1Client(evil, PASSWORD)
    fid = c.upload("transfer.txt", TRANSFER)
    evil.tamper_content(fid, POS, b"0100", b"9100")
    assert c.download(fid) == TRANSFER.replace(b"$0100", b"$9100")


def test_t3_v1_tamper_content_later_block(evil):
    """T3：V1 竄改非首區塊——目標位元組被改寫、前一區塊變亂碼，客戶端仍照單全收。"""
    c = V1Client(evil, PASSWORD)
    fid = c.upload("invoice.txt", BLOCKY)
    evil.tamper_content(fid, POS_BLOCK1, b"0100", b"9100")
    out = c.download(fid)  # 不拋例外 = 客戶端接受
    assert out[POS_BLOCK1 : POS_BLOCK1 + 4] == b"9100"
    assert out[:16] != BLOCKY[:16]  # 前一區塊被犧牲
    assert out[32:] == BLOCKY[32:]  # 之後的區塊不受影響


def test_t6_v2_tamper_content(evil):
    """T6：V2 竄改內容 → IntegrityError。"""
    c = V2Client(evil, PASSWORD)
    fid = c.upload("transfer.txt", TRANSFER)
    evil.tamper_content(fid, POS, b"0100", b"9100")
    with pytest.raises(IntegrityError):
        c.download(fid)


# ---------- 攻擊 2：植入檔案 ----------


def test_t4_v1_inject_file(evil):
    """T4：V1 清單出現非使用者上傳的檔案，且可正常開啟。"""
    c = V1Client(evil, PASSWORD)
    real = c.upload("report.pdf", b"real report")
    fake = evil.inject_file("confession.txt")
    listing = dict(c.list_files())
    assert fake != real
    assert listing[fake] == "confession.txt"
    c.download(fake)  # 不拋例外 = 看起來像使用者自己上傳的


def test_t7_v2_inject_file(evil):
    """T7：V2 清單驗證失敗 → IntegrityError；直接下載偽造檔也被拒絕。"""
    c = V2Client(evil, PASSWORD)
    c.upload("report.pdf", b"real report")
    fake = evil.inject_file("confession.txt")
    with pytest.raises(IntegrityError):
        c.list_files()
    with pytest.raises(IntegrityError):
        c.download(fake)


def test_inject_file_requires_existing_record(evil):
    with pytest.raises(ValueError):
        evil.inject_file("x.txt")


# ---------- 攻擊 3：對調檔名 ----------


def test_t5_v1_swap_names(evil):
    """T5：V1 開啟 a.txt 卻得到 b.txt 的內容。"""
    c = V1Client(evil, PASSWORD)
    a = c.upload("a.txt", b"content of A")
    b = c.upload("b.txt", b"content of B")
    evil.swap_names(a, b)
    assert c.download(_by_name(c)["a.txt"]) == b"content of B"


def test_t8_v2_swap_names(evil):
    """T8：V2 對調檔名 → IntegrityError（清單或 AAD 驗證失敗）。"""
    c = V2Client(evil, PASSWORD)
    a = c.upload("a.txt", b"content of A")
    b = c.upload("b.txt", b"content of B")
    evil.swap_names(a, b)
    with pytest.raises(IntegrityError):
        c.list_files()
    with pytest.raises(IntegrityError):
        c.download(a)
