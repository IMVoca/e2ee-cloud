"""線下互動模擬器驗收測試（規格：docs/SIM_SPEC.md）。

由 Claude 撰寫的驗收材料；實作者不得修改本檔。
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from server.malicious import MaliciousServer
from simulate import Result, Simulator

REPO = Path(__file__).resolve().parents[1]
SCENARIOS = sorted((REPO / "scenarios").glob("*.sim"))
PW = "s3cret-Pa55"
TRANSFER = "Transfer $0100 to Alice. Approved by Bob."


@pytest.fixture
def sim(tmp_path):
    return Simulator(tmp_path / "sim")


def run(sim, *lines):
    """逐行執行，回傳最後一個 Result。"""
    result = None
    for line in lines:
        result = sim.execute(line)
        assert isinstance(result, Result)
    return result


# ---------- 基本指令與錯誤處理 ----------


def test_help_lists_commands(sim):
    r = sim.execute("help")
    assert r.status == "ok"
    for word in ("login", "upload", "cat", "attack", "expect", "reset"):
        assert word in r.text


def test_blank_and_comment_lines(sim):
    assert sim.execute("") == Result("ok", "")
    assert sim.execute("   # 註解") == Result("ok", "")


@pytest.mark.parametrize("line", [
    "frobnicate", "ls", "upload a.txt hi", "cat #1", "server ls",
    "attack swap #1 #2", "login v3 pw", "login v1", 'upload "unterminated',
])
def test_usage_errors_never_raise(sim, line):
    """未登入、未知指令、參數錯誤 → usage，且 execute 不得拋例外。"""
    assert sim.execute(line).status == "usage"


def test_login_sets_version_and_server(sim):
    assert sim.version is None and sim.server is None
    assert run(sim, f"login v2 {PW}").status == "ok"
    assert sim.version == "v2"
    assert isinstance(sim.server, MaliciousServer)


# ---------- T1：正常操作 ----------


@pytest.mark.parametrize("ver", ["v1", "v2"])
def test_upload_ls_cat(sim, ver):
    run(sim, f"login {ver} {PW}")
    up = sim.execute("upload hello.txt Hello, E2EE cloud!")
    assert up.status == "ok" and "#1" in up.text
    ls = sim.execute("ls")
    assert ls.status == "ok" and "hello.txt" in ls.text
    for target in ("hello.txt", "#1"):
        r = sim.execute(f"cat {target}")
        assert r.status == "ok" and "Hello, E2EE cloud!" in r.text


@pytest.mark.parametrize("ver", ["v1", "v2"])
def test_upload_file_and_save_binary_roundtrip(sim, tmp_path, ver):
    """Windows 路徑（含反斜線）必須原樣傳入；二進位內容逐位元組相同。"""
    data = os.urandom(5000) + b"\x00\xff"
    src = tmp_path / "in dir" / "photo.bin"
    src.parent.mkdir()
    src.write_bytes(data)
    out = tmp_path / "out.bin"
    run(sim, f"login {ver} {PW}")
    assert sim.execute(f'upload-file "{src}"').status == "ok"
    cat = sim.execute("cat photo.bin")
    assert cat.status == "ok" and "5002 bytes" in cat.text
    assert sim.execute(f'save #1 "{out}"').status == "ok"
    assert out.read_bytes() == data


def test_cat_crlf_text_shown_as_text(sim, tmp_path):
    """Windows 記事本存的 CRLF 文字檔要當文字顯示，不是 hex。"""
    src = tmp_path / "notes.txt"
    src.write_bytes("第一行\r\nsecond line\r\n".encode("utf-8"))
    run(sim, f"login v1 {PW}", f'upload-file "{src}"')
    r = sim.execute("cat notes.txt")
    assert r.status == "ok" and "second line" in r.text and "bytes>" not in r.text


def test_expect_display_has_single_prefix(tmp_path):
    log = tmp_path / "x.log"
    s = Simulator(tmp_path / "sim", log_path=log)
    run(s, f"login v1 {PW}", "expect ok")
    assert "[成功] [EXPECT" not in log.read_text(encoding="utf-8")


def test_apostrophe_in_free_text(sim):
    """英文撇號不是引號：upload / expect 的自由文字要能含 it's。"""
    run(sim, f"login v1 {PW}")
    assert sim.execute("upload memo.txt it's Bob's plan").status == "ok"
    r = sim.execute("cat memo.txt")
    assert r.status == "ok" and "it's Bob's plan" in r.text
    assert sim.execute("expect contains Bob's plan").status == "ok"
    assert sim.execute("cat 'memo.txt").status == "usage"  # 其他指令仍視為引號錯誤
    assert sim.execute('upload quote.txt He said "hi"  twice').status == "ok"
    r = sim.execute("cat quote.txt")
    assert r.text.endswith('He said "hi"  twice')  # 引號與連續空白逐字保留
    assert sim.execute('expect contains said "hi"').status == "ok"


def test_id_prefix_target(sim):
    run(sim, f"login v1 {PW}", "upload a.txt alpha")
    fid = sim.server.list()[0]["file_id"]
    assert "alpha" in sim.execute(f"cat {fid[:8]}").text
    assert sim.execute("cat zz").status == "usage"  # 前綴太短且無此檔名


def test_journal_persists_across_restart(tmp_path):
    root = tmp_path / "sim"
    run(Simulator(root), f"login v1 {PW}", "upload a.txt alpha", "upload b.txt beta")
    again = Simulator(root)
    r = run(again, f"login v1 {PW}", "cat #2")
    assert r.status == "ok" and "beta" in r.text


# ---------- 攻擊：V1 成功、V2 拒絕 ----------


def test_v1_tamper_succeeds(sim):
    run(sim, f"login v1 {PW}", f"upload transfer.txt {TRANSFER}")
    atk = sim.execute("attack tamper #1 10 0100 9100")
    assert atk.status == "ok" and "已修改欄位" in atk.text and "nonce_or_iv" in atk.text
    r = sim.execute("cat transfer.txt")
    assert r.status == "ok" and TRANSFER.replace("$0100", "$9100") in r.text


def test_v2_tamper_rejected(sim):
    run(sim, f"login v2 {PW}", f"upload transfer.txt {TRANSFER}")
    assert sim.execute("attack tamper #1 10 0100 9100").status == "ok"
    r = sim.execute("cat transfer.txt")
    assert r.status == "rejected" and "IntegrityError" in r.text


def test_tamper_bad_args_is_error(sim):
    """伺服器端參數檢查（跨區塊、長度不同）拋 ValueError → error。"""
    run(sim, f"login v1 {PW}", f"upload transfer.txt {TRANSFER}")
    r = sim.execute("attack tamper #1 14 0100 9100")
    assert r.status == "error" and "ValueError" in r.text
    assert sim.execute("attack tamper #1 10 0100 91").status == "error"
    assert sim.execute("attack tamper #1 ten 0100 9100").status == "usage"


def test_v1_inject_succeeds(sim):
    run(sim, f"login v1 {PW}", "upload report.pdf real report")
    atk = sim.execute("attack inject confession.txt #1")
    assert atk.status == "ok" and "#2" in atk.text and "新增記錄" in atk.text
    assert "confession.txt" in sim.execute("ls").text
    r = sim.execute("cat confession.txt")
    assert r.status == "ok" and "real report" in r.text


def test_v2_inject_rejected(sim):
    run(sim, f"login v2 {PW}", "upload report.pdf real report",
        "attack inject confession.txt")
    assert sim.execute("ls").status == "rejected"
    assert sim.execute("cat #2").status == "rejected"
    assert sim.execute("cat #1").status == "ok"  # 未被動過的原檔仍可下載


def test_v1_swap_succeeds(sim):
    run(sim, f"login v1 {PW}", "upload a.txt content of A", "upload b.txt content of B")
    atk = sim.execute("attack swap a.txt b.txt")
    assert atk.status == "ok" and "name" in atk.text
    r = sim.execute("cat a.txt")
    assert r.status == "ok" and "content of B" in r.text


def test_v2_swap_rejected_and_names_not_targetable(sim):
    run(sim, f"login v2 {PW}", "upload a.txt content of A", "upload b.txt content of B")
    # V2 攻擊者看不到明文檔名，不能用檔名指定目標
    assert sim.execute("attack swap a.txt b.txt").status == "usage"
    assert sim.execute("attack swap #1 #2").status == "ok"
    assert sim.execute("ls").status == "rejected"
    assert sim.execute("cat a.txt").status == "rejected"
    assert sim.execute("cat #1").status == "rejected"


def test_server_view_v1_plaintext_v2_hidden(sim):
    run(sim, f"login v1 {PW}", "upload diary.txt my diary")
    assert "diary.txt" in sim.execute("server ls").text
    run(sim, f"login v2 {PW}", "upload diary.txt my diary")
    view = sim.execute("server ls")
    assert view.status == "ok" and "diary.txt" not in view.text
    show = sim.execute("server show #1")
    assert show.status == "ok" and "my diary" not in show.text and "…" in show.text


# ---------- T2：密碼錯誤 ----------


def test_wrong_password(sim):
    run(sim, "login v1 right", "upload s.txt TOP SECRET", "login v1 wrong")
    assert "TOP SECRET" not in sim.execute("cat #1").text
    run(sim, "login v2 right", "upload s.txt TOP SECRET", "login v2 wrong")
    assert sim.execute("ls").status == "rejected"
    r = sim.execute("cat #1")
    assert r.status == "rejected" and "TOP SECRET" not in r.text


# ---------- 回滾：V2 已知限制 ----------


def test_snapshot_rollback_server_methods(tmp_path):
    evil = MaliciousServer(tmp_path / "s")
    evil.put({"file_id": "aaaa", "name": "x", "wrapped_key": "", "nonce_or_iv": "",
              "ciphertext": "", "version": 1})
    evil.put_meta("manifest", {"entries": [], "mac": "old"})
    evil.snapshot("t0")
    evil.put({"file_id": "bbbb", "name": "y", "wrapped_key": "", "nonce_or_iv": "",
              "ciphertext": "", "version": 1})
    evil.put_meta("manifest", {"entries": [], "mac": "new"})
    evil.rollback("t0")
    assert [r["file_id"] for r in evil.list()] == ["aaaa"]
    assert evil.get_meta("manifest")["mac"] == "old"
    with pytest.raises(KeyError):
        evil.rollback("nope")
    with pytest.raises(ValueError):
        evil.snapshot("../escape")


def test_v2_rollback_undetected(sim):
    run(sim, f"login v2 {PW}", "upload contract.txt price = 100",
        "server snapshot before", "upload invoice.txt pay 5000")
    assert sim.execute("attack rollback before").status == "ok"
    ls = sim.execute("ls")
    assert ls.status == "ok"
    assert "contract.txt" in ls.text and "invoice.txt" not in ls.text


# ---------- expect ----------


def test_expect_semantics(sim):
    assert sim.execute("expect ok").status == "failed"  # 尚無上一個結果
    run(sim, f"login v1 {PW}", "upload a.txt hello world")
    assert sim.execute("expect ok").status == "ok"
    assert sim.execute("expect contains #1").status == "ok"  # 仍比對 upload 的結果
    assert sim.execute("expect rejected").status == "failed"
    assert sim.execute("expect not-contains #1").status == "failed"
    sim.execute("cat a.txt")
    assert sim.execute("expect contains hello world").status == "ok"
    assert sim.execute("expect maybe").status == "usage"


# ---------- reset ----------


def test_reset_only_removes_version_dirs(tmp_path):
    root = tmp_path / "sim"
    keep = root / "keep.txt"
    s = Simulator(root)
    run(s, f"login v1 {PW}", "upload a.txt alpha", f"login v2 {PW}", "upload b.txt beta")
    keep.write_text("do not delete")
    assert s.execute("reset v2").status == "ok"
    assert s.version is None and not (root / "v2").exists() and (root / "v1").exists()
    assert s.execute("reset all").status == "ok"
    assert not (root / "v1").exists() and keep.exists()
    assert s.execute("reset v9").status == "usage"


# ---------- 紀錄檔 ----------


def test_log_masks_password(tmp_path):
    log = tmp_path / "run.log"
    s = Simulator(tmp_path / "sim", log_path=log)
    run(s, f"login v1 {PW}", "upload a.txt hello", "cat a.txt", "# 註解不記錄")
    text = log.read_text(encoding="utf-8")
    assert PW not in text
    assert "login v1 ****" in text
    assert "upload a.txt hello" in text and "[成功]" in text
    assert "註解不記錄" not in text


# ---------- CLI 與情境腳本 ----------


def _cli(*args, cwd):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, str(REPO / "simulate.py"), *args],
                          cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", timeout=180)


def test_scenarios_exist():
    assert len(SCENARIOS) == 5


@pytest.mark.parametrize("script", SCENARIOS, ids=lambda p: p.name)
def test_scenario_passes_via_cli(tmp_path, script):
    log = tmp_path / "scenario.log"
    proc = _cli("--root", str(tmp_path / "sim"), "--script", str(script),
                "--log", str(log), cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[EXPECT 失敗]" not in proc.stdout
    assert "[EXPECT 通過]" in proc.stdout
    assert log.exists() and "[EXPECT 通過]" in log.read_text(encoding="utf-8")


def test_cli_script_failure_exit_code(tmp_path):
    bad = tmp_path / "bad.sim"
    bad.write_text("login v1 pw\nupload a.txt hi\nexpect rejected\n", encoding="utf-8")
    proc = _cli("--root", str(tmp_path / "sim"), "--script", str(bad), "--no-log",
                cwd=tmp_path)
    assert proc.returncode == 1
    assert "[EXPECT 失敗]" in proc.stdout


def test_cli_interactive_via_stdin(tmp_path):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    proc = subprocess.run(
        [sys.executable, str(REPO / "simulate.py"), "--root", str(tmp_path / "sim"),
         "--no-log"],
        input="login v1 pw\nupload a.txt 中文內容\ncat a.txt\nquit\n",
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8",
        timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "中文內容" in proc.stdout
    assert not list((tmp_path).glob("logs/*.log"))  # --no-log 不寫紀錄
