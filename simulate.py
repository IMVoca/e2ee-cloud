"""離線互動模擬器：操作使用者端，觀察惡意伺服器的攻擊。"""

from __future__ import annotations

import argparse
import getpass
import json
import shlex
import shutil
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from common.errors import IntegrityError
from common.record import b64d
from server.malicious import MaliciousServer
from v1.client import Client as V1Client
from v2.client import Client as V2Client


class Result(NamedTuple):
    status: str
    text: str


class UsageError(Exception):
    """指令語法、登入狀態或目標不符合要求。"""


PREFIXES = {
    "ok": "[成功]",
    "rejected": "[偵測並拒絕]",
    "error": "[錯誤]",
    "usage": "[指令錯誤]",
    "failed": "[EXPECT 失敗]",
}

HELP = """login <v1|v2> <password>：登入指定版本的工作區
upload <name> <text...>：加密並上傳文字
upload-file <local_path> [name]：加密並上傳本機檔案
ls：依檔名列出使用者的檔案
cat <target>：下載並顯示內容
save <target> <local_path>：下載並儲存原始內容
server ls：列出伺服器看得到的原始記錄
server show <target>：顯示原始 JSON，截短較長的 base64 欄位
server snapshot <label>：保存伺服器快照
attack tamper <target> <pos> <original> <replacement>：竄改 IV 或密文
attack inject <fake_name> [source_target]：複製密文並植入新記錄
attack swap <target_a> <target_b>：對調記錄的名稱欄位
attack rollback <label>：還原快照中的檔案與中繼資料
help：顯示指令說明
status：顯示目前工作區與紀錄檔資訊
reset <v1|v2|all>：清除指定版本的工作區
expect <ok|rejected|error>：驗證上一個操作的狀態
expect contains <text...>：驗證上一個結果包含文字
expect not-contains <text...>：驗證上一個結果不含文字
quit / exit：結束操作"""


def _lexer(line: str) -> shlex.shlex:
    lex = shlex.shlex(line, posix=True)
    lex.whitespace_split = True
    lex.escape = ""
    lex.commenters = ""
    return lex


def _visible_line(line: str) -> str:
    """連語法錯誤的登入指令也必須遮蔽密碼。"""
    lex = _lexer(line)
    try:
        command = next(lex, "")
    except ValueError:
        return "（指令名稱無法解析，已隱藏）"
    if command.lower() == "login":
        try:
            version = next(lex, "")
        except ValueError:
            version = ""
        if version.lower() in ("v1", "v2"):
            return f"login {version} ****"
        return "login ****"
    return line


def _display(result: Result) -> str:
    if result.status == "failed" or result.text.startswith("[EXPECT 通過]"):
        return result.text
    return f"{PREFIXES[result.status]} {result.text}"


class Simulator:
    def __init__(self, root: str | Path = "sim_storage",
                 log_path: str | Path | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.log_path = Path(log_path) if log_path is not None else None
        self.version: str | None = None
        self.server: MaliciousServer | None = None
        self.client: V1Client | V2Client | None = None
        self._journal: list[str] = []
        self._previous: Result | None = None
        self._quit = False

    @property
    def prompt(self) -> str:
        return f"sim({self.version or '-'})> "

    def execute(self, line: str) -> Result:
        """所有操作與紀錄錯誤都轉成結果，不向呼叫者拋出例外。"""
        tokens = []
        prompt = self.prompt
        try:
            if not line.strip() or line.lstrip().startswith("#"):
                return Result("ok", "")
            if line.split()[0].lower() in ("upload", "expect"):
                tokens = line.strip().split(maxsplit=2)
            else:
                try:
                    tokens = list(_lexer(line))
                except ValueError as exc:
                    raise UsageError("指令引號未閉合") from exc
            result = self._dispatch(tokens)
        except IntegrityError as exc:
            result = Result("rejected", f"IntegrityError：{exc}")
        except UsageError as exc:
            result = Result("usage", str(exc))
        except Exception as exc:
            result = Result("error", f"{type(exc).__name__}：{exc}")
        try:
            self._log(line, prompt, result)
        except Exception as exc:
            result = Result("error", f"{type(exc).__name__}：寫入紀錄檔失敗：{exc}")
        if not tokens or tokens[0].lower() != "expect":
            self._previous = result
        return result

    def _log(self, line: str, prompt: str, result: Result) -> None:
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] "
                             f"{prompt}{_visible_line(line)}\n{_display(result)}\n")
                stream.flush()

    def _remember(self, file_id: str) -> str:
        self._journal.append(file_id)
        path = self.root / self.version / "journal.json"
        path.write_text(json.dumps(self._journal), encoding="utf-8")
        return self._label(file_id)

    def _label(self, file_id: str) -> str:
        if file_id in self._journal:
            return f"#{self._journal.index(file_id) + 1}  {file_id}"
        return file_id

    def _target(self, target: str, user: bool = False) -> str:
        """先依伺服器觀察到的編號與 ID 解析，必要時才查檔名。"""
        if target.startswith("#") and target[1:].isascii() and target[1:].isdigit():
            index = int(target[1:]) - 1
            if 0 <= index < len(self._journal):
                return self._journal[index]
        records = self.server.list()
        if len(target) >= 4:
            matches = [r["file_id"] for r in records if r["file_id"].startswith(target)]
            if len(matches) == 1:
                return matches[0]
        if user:
            matches = [fid for fid, name in self.client.list_files() if name == target]
        elif self.version == "v1":
            matches = [r["file_id"] for r in records if r["name"] == target]
        else:
            matches = []
        if len(matches) != 1:
            raise UsageError(f"目標不存在或不唯一：{target}")
        return matches[0]

    def _expect(self, args: list[str]) -> Result:
        if args:
            args = [args[0].lower(), *args[1:]]
        if len(args) == 1 and args[0] in ("ok", "rejected", "error"):
            expected = f"狀態為 {args[0]}"
            actual = self._previous.status if self._previous else "尚無上一個結果"
            passed = self._previous is not None and actual == args[0]
        elif len(args) >= 2 and args[0] in ("contains", "not-contains"):
            text = " ".join(args[1:])
            expected = f"{'包含' if args[0] == 'contains' else '不含'} {text!r}"
            actual = self._previous.text if self._previous else "尚無上一個結果"
            passed = self._previous is not None and ((text in actual) == (args[0] == "contains"))
        else:
            raise UsageError("用法：expect <ok|rejected|error> 或 expect <contains|not-contains> <文字>")
        if passed:
            return Result("ok", f"[EXPECT 通過] 預期{expected}")
        return Result("failed", f"[EXPECT 失敗] 預期{expected}；實際：{actual}")

    def _reset(self, version: str) -> None:
        versions = ("v1", "v2") if version == "all" else (version,)
        root = self.root.resolve()
        paths = [root / ver for ver in versions]
        # 遞迴刪除前驗證所有絕對路徑，拒絕指向其他位置的連結。
        if any(path.resolve() != path or path.parent != root for path in paths):
            raise UsageError("工作區路徑不安全，無法清除")
        for ver, path in zip(versions, paths):
            if path.exists():
                shutil.rmtree(path)
            if self.version == ver:
                self.version = self.server = self.client = None
                self._journal = []

    def _dispatch(self, tokens: list[str]) -> Result:
        command, *args = tokens
        command = command.lower()
        if command == "expect":
            return self._expect(args)
        if command == "help" and not args:
            return Result("ok", HELP)
        if command in ("quit", "exit") and not args:
            self._quit = True
            return Result("ok", "操作結束")
        if command == "status" and not args:
            workspace = self.root / self.version if self.version else self.root
            count = len(self.server.list()) if self.server else 0
            return Result("ok", f"版本：{self.version or '尚未登入'}\n工作區：{workspace}\n"
                          f"記錄筆數：{count}\n紀錄檔：{self.log_path or '未啟用'}")
        if command == "reset" and len(args) == 1 and args[0].lower() in ("v1", "v2", "all"):
            self._reset(args[0].lower())
            return Result("ok", f"已清除工作區：{args[0]}")
        if command == "login" and len(args) == 2 and args[0].lower() in ("v1", "v2"):
            version = args[0].lower()
            workspace = self.root / version
            server = MaliciousServer(workspace)
            client = (V1Client if version == "v1" else V2Client)(server, args[1])
            journal_path = workspace / "journal.json"
            journal = json.loads(journal_path.read_text(encoding="utf-8")) if journal_path.exists() else []
            if not isinstance(journal, list) or not all(isinstance(fid, str) for fid in journal):
                raise ValueError("上傳順序紀錄必須是 file_id 字串陣列")
            self.version, self.server, self.client = version, server, client
            self._journal = journal
            return Result("ok", f"已登入 {version}，工作區：{workspace}")
        if command in ("login", "reset", "help", "status", "quit", "exit"):
            raise UsageError("指令參數錯誤，請參閱 help")
        if self.server is None:
            raise UsageError("請先 login <v1|v2> <password>")
        if command == "upload" and len(args) >= 2:
            fid = self.client.upload(args[0], " ".join(args[1:]).encode("utf-8"))
            return Result("ok", f"已上傳 {self._remember(fid)}")
        if command == "upload-file" and len(args) in (1, 2):
            path = Path(args[0])
            fid = self.client.upload(args[1] if len(args) == 2 else path.name, path.read_bytes())
            return Result("ok", f"已上傳 {self._remember(fid)}")
        if command == "ls" and not args:
            files = sorted(self.client.list_files(), key=lambda entry: entry[1])
            return Result("ok", "\n".join(f"{self._label(fid)}  {name}" for fid, name in files)
                          or "(沒有檔案)")
        if (command == "cat" and len(args) == 1) or (command == "save" and len(args) == 2):
            data = self.client.download(self._target(args[0], user=True))
            if command == "save":
                Path(args[1]).write_bytes(data)
                return Result("ok", f"已儲存 {len(data)} bytes 至 {args[1]}")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None and all(
                ch in "\n\t\r" or unicodedata.category(ch) != "Cc" for ch in text
            ):
                return Result("ok", text)
            return Result("ok", f"<{len(data)} bytes>\n{data[:64].hex()}")
        if command == "server":
            return self._server_command(args)
        if command == "attack":
            return self._attack(args)
        raise UsageError("未知指令或參數錯誤，請參閱 help")

    def _server_command(self, args: list[str]) -> Result:
        if args and args[0].lower() == "ls" and len(args) == 1:
            lines = []
            for record in self.server.list():
                name = record["name"] if record["version"] == 1 else record["name"][:16] + "…"
                size = len(b64d(record["ciphertext"]))
                lines.append(f"{self._label(record['file_id'])}  version={record['version']}  "
                             f"{name}  {size} bytes")
            return Result("ok", "\n".join(lines) or "(沒有檔案)")
        if args and args[0].lower() == "show" and len(args) == 2:
            record = self.server.get(self._target(args[1]))
            fields = ["wrapped_key", "nonce_or_iv", "ciphertext"]
            if record["version"] == 2:
                fields.append("name")
            for field in fields:
                value = record[field]
                if len(value) > 48:
                    record[field] = f"{value[:48]}…({len(b64d(value))} bytes)"
            return Result("ok", json.dumps(record, ensure_ascii=False, indent=2))
        if args and args[0].lower() == "snapshot" and len(args) == 2:
            self.server.snapshot(args[1])
            return Result("ok", f"已保存快照：{args[1]}")
        raise UsageError("用法：server ls / show <目標> / snapshot <標籤>")

    def _attack(self, args: list[str]) -> Result:
        if not args:
            raise UsageError("請指定 attack 的操作，詳見 help")
        operation = args[0].lower()
        if operation == "rollback" and len(args) == 2:
            self.server.rollback(args[1])
            return Result("ok", f"已還原快照：{args[1]}")
        if operation == "inject" and len(args) in (2, 3):
            source = self._target(args[2]) if len(args) == 3 else None
            fid = self.server.inject_file(args[1], source)
            return Result("ok", f"已修改欄位：新增記錄 {fid}\n{self._remember(fid)}")
        if operation == "tamper" and len(args) == 5:
            try:
                position = int(args[2])
            except ValueError as exc:
                raise UsageError("竄改位置必須是整數") from exc
            fid = self._target(args[1])
            before = [self.server.get(fid)]
            self.server.tamper_content(fid, position, args[3].encode(), args[4].encode())
        elif operation == "swap" and len(args) == 3:
            a, b = self._target(args[1]), self._target(args[2])
            before = [self.server.get(a), self.server.get(b)]
            self.server.swap_names(a, b)
        else:
            raise UsageError("攻擊指令參數錯誤，請參閱 help")
        changes = []
        for old in before:
            new = self.server.get(old["file_id"])
            fields = sorted(key for key in old.keys() | new.keys() if old.get(key) != new.get(key))
            changes.append(f"{self._label(old['file_id'])}：{', '.join(fields) or '無變更'}")
        return Result("ok", "已修改欄位：\n" + "\n".join(changes))

    def run_script(self, path: str | Path, echo: bool = True) -> int:
        failures = 0
        self._quit = False
        with Path(path).open(encoding="utf-8-sig") as script:
            for raw_line in script:
                line = raw_line.rstrip("\r\n")
                if echo:
                    if not line.strip():
                        print()
                    elif line.lstrip().startswith("#"):
                        print(line)
                    else:
                        print(self.prompt + _visible_line(line))
                result = self.execute(line)
                if result.text:
                    print(_display(result))
                failures += result.status in ("failed", "usage")
                if self._quit:
                    break
        return failures


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="離線互動模擬惡意伺服器攻擊")
    parser.add_argument("--root", default="sim_storage", help="工作區根目錄")
    parser.add_argument("--script", help="逐行執行的情境腳本")
    logging = parser.add_mutually_exclusive_group()
    logging.add_argument("--log", help="UTF-8 紀錄檔路徑")
    logging.add_argument("--no-log", action="store_true", help="停用紀錄檔")
    args = parser.parse_args(argv)
    log_path = None if args.no_log else args.log or f"logs/sim-{datetime.now():%Y%m%d-%H%M%S}.log"
    try:
        simulator = Simulator(args.root, log_path)
        if args.script:
            return int(simulator.run_script(args.script) > 0)
        print("E2EE 迷你雲端 — 線下互動模擬器")
        print("輸入 help 查看指令；login v1 不帶密碼可隱藏輸入")
        print(f"工作區：{simulator.root}\n紀錄檔：{simulator.log_path or '未啟用'}")
        while not simulator._quit:
            try:
                line = input(simulator.prompt)
                if sys.stdin.isatty():
                    try:
                        tokens = list(_lexer(line))
                    except ValueError:
                        tokens = []  # 語法錯誤交由 execute 統一處理。
                    if (len(tokens) == 2 and tokens[0].lower() == "login"
                            and tokens[1].lower() in ("v1", "v2")):
                        password = getpass.getpass("密碼：")
                        line += " " + shlex.quote(password)
            except (EOFError, KeyboardInterrupt):
                break
            result = simulator.execute(line)
            if result.text:
                print(_display(result))
        return 0
    except Exception as exc:
        print(f"[錯誤] {type(exc).__name__}：{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
