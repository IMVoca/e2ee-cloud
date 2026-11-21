# 線下互動模擬器規格（SIM v1.3）

> 架構與驗收：Claude　｜　實作：Codex
> 驗收標準 = `pytest` 全數通過（含既有 47 項與 `tests/test_simulator.py`），且 `scenarios/*.sim` 以 `--script` 執行時結束碼皆為 0。
> **測試檔與 `scenarios/*.sim` 是規格的一部分，實作者不得修改。**

## 0. 目的

`demo.py` 是一鍵自動展示；本模擬器讓操作者在**完全離線**的終端機中，自己扮演「使用者」與「惡意伺服器」，
一步步上傳、下載、發動攻擊、切換 V1／V2，並在畫面上看到伺服器 JSON 被改了哪些欄位。
每次操作都寫入紀錄檔，情境腳本內建 `expect` 斷言，可重跑作為驗證證據。

## 1. 檔案與範圍

| 檔案 | 動作 | 說明 |
|---|---|---|
| `simulate.py` | 新增 | 模擬器本體與 CLI 入口 |
| `server/malicious.py` | 新增兩個方法 | `snapshot(label)`、`rollback(label)`（第 5 節）；既有三個方法與行為不得改動 |
| `.gitignore` | 追加 | `sim_storage/`、`logs/` |
| `tests/test_simulator.py`、`scenarios/*.sim` | **不得修改** | 由 Claude 撰寫的驗收材料 |

不得修改：`common/*`、`server/storage.py`、`v1/client.py`、`v2/client.py`、既有 `tests/*`、`docs/SPEC.md`。
只用 Python 標準函式庫與既有相依套件（`cryptography`）；不得連網。

## 2. 公開介面（測試直接使用）

```python
# simulate.py
from typing import NamedTuple

class Result(NamedTuple):
    status: str   # "ok" | "rejected" | "error" | "usage" | "failed"
    text: str     # 給人看的輸出（多行可）

class Simulator:
    def __init__(self, root: str | Path = "sim_storage", log_path: str | Path | None = None): ...
    def execute(self, line: str) -> Result: ...
    def run_script(self, path: str | Path, echo: bool = True) -> int: ...   # 回傳失敗數
    version: str | None          # "v1" / "v2"；尚未 login 為 None
    server: MaliciousServer | None   # 目前工作區的伺服器

def main(argv: list[str] | None = None) -> int: ...
```

### 2.1 狀態語意

| status | 意義 | 顯示前綴 |
|---|---|---|
| `ok` | 指令成功（含 `expect` 通過） | `[成功]` |
| `rejected` | 客戶端拋出 `IntegrityError`（V2 偵測到攻擊） | `[偵測並拒絕]` |
| `error` | 其他例外（如 V1 unpad 失敗的 `ValueError`、檔案不存在的 `KeyError`） | `[錯誤]` |
| `usage` | 指令打錯、參數錯、尚未 login、目標無法解析 | `[指令錯誤]` |
| `failed` | `expect` 斷言不成立 | `[EXPECT 失敗]` |

- `execute()` **永遠不得往外拋例外**；所有例外都轉成上表狀態。
- `rejected` 的 `text` 必須包含字串 `IntegrityError`。
- `error` 的 `text` 必須包含例外類別名稱（如 `ValueError`）。

## 3. 指令語法

**斷詞**：`lex = shlex.shlex(line, posix=True); lex.whitespace_split = True; lex.escape = ""; lex.commenters = ""`。
（關閉反斜線跳脫，Windows 路徑 `C:\Users\...` 才能原樣傳入；可用單／雙引號包住含空白的參數。）
斷詞錯誤（如引號未閉合）→ `usage`。
**自由文字例外（v1.3）**：第一個字為 `upload` 或 `expect`（不分大小寫）時**不使用 shlex**，改以 `line.strip().split(maxsplit=2)` 切出「指令、第二個字、其餘原文」，其餘原文逐字保留（含撇號、引號、連續空白）。因此 `upload` 的檔名不可含空白（需要時用 `upload-file <path> "<name>"`）。（v1.2 的「斷詞失敗才改用空白切分」不正確：偶數個撇號不會觸發錯誤，而會被 shlex 靜默吃掉，例如 `it's Bob's` → `its Bobs`。）
指令名稱不分大小寫。

### 3.1 使用者端（呼叫 V1/V2 Client）

| 指令 | 行為 |
|---|---|
| `login <v1\|v2> <password>` | 切換到工作區 `root/<ver>/`，建立 `MaliciousServer(root/<ver>)` 與對應 Client。可重複 login（換密碼或換版本）。成功輸出包含版本與工作區路徑。 |
| `upload <name> <text...>` | 內容 = 該行第二個字之後的原文（見 v1.3 自由文字例外）`.encode("utf-8")`；上傳後輸出 `#N` 與 file_id。缺少 text → `usage`。 |
| `upload-file <local_path> [name]` | 讀本機檔案原始 bytes 上傳；`name` 預設為檔名（`Path(p).name`）。 |
| `ls` | 呼叫 `client.list_files()`，逐行輸出 `#N  <file_id>  <name>`（無 `#N` 時省略），依名稱排序；空清單輸出 `(沒有檔案)`。 |
| `cat <target>` | 下載並顯示內容：可解成 UTF-8 且無控制字元（`\n`、`\t` 除外）→ 原文；否則輸出 `<N bytes>` 與前 64 bytes 的 hex。 |
| `save <target> <local_path>` | 下載並寫入本機檔案（原始 bytes），輸出 bytes 數。 |

### 3.2 伺服器／攻擊者端（只能用伺服器看得到的資料）

| 指令 | 行為 |
|---|---|
| `server ls` | 列出目前版本的**原始記錄**：`#N`、file_id、version、`name`（V1 明文；V2 取前 16 字元加 `…`）、ciphertext bytes 數。 |
| `server show <target>` | 印出該筆 JSON；超過 48 字元的 base64 欄位截斷為前 48 字元加 `…(<解碼後 bytes> bytes)`。 |
| `attack tamper <target> <pos> <original> <replacement>` | 呼叫 `server.tamper_content(fid, int(pos), original.encode(), replacement.encode())`。 |
| `attack inject <fake_name> [source_target]` | 呼叫 `server.inject_file(fake_name, source_fid 或 None)`；新 ID 記入 journal 並輸出 `#N`。 |
| `attack swap <target_a> <target_b>` | 呼叫 `server.swap_names(a, b)`。 |
| `server snapshot <label>` | 呼叫 `server.snapshot(label)`。 |
| `attack rollback <label>` | 呼叫 `server.rollback(label)`。 |

三個 `attack tamper/inject/swap` 成功時，輸出必須包含 `已修改欄位：` 後接被改動的欄位名（比對攻擊前後記錄 dict 的差異；inject 則列出 `新增記錄 <file_id>`）。
攻擊指令自身的參數錯誤（伺服器拋 `ValueError`）→ `error`。

### 3.3 其他

| 指令 | 行為 |
|---|---|
| `help` | 列出所有指令與一句說明（中文）。 |
| `status` | 目前版本、工作區路徑、記錄筆數、紀錄檔路徑。 |
| `reset <v1\|v2\|all>` | 刪除 `root/v1`、`root/v2`（或兩者）整個資料夾；若刪到目前工作區則登出（`version` 變 `None`）。**只能刪除 `root` 底下的 `v1`/`v2` 子資料夾**，`root` 本身保留。 |
| `expect <ok\|rejected\|error>` | 斷言「上一個非 expect、非註解指令」的 status。 |
| `expect contains <text...>` / `expect not-contains <text...>` | 斷言上一個結果的 `text` 是否包含該行第二個字之後的原文（見 v1.3）。 |
| `quit` / `exit` | 互動模式結束；腳本模式忽略之後的行。 |

`expect` 成立 → `Result("ok", "[EXPECT 通過] ...")`；不成立 → `Result("failed", ...)`，並說明預期與實際。
尚無上一個結果時 → `failed`。

### 3.4 目標（target）解析

依序嘗試，第一個成功者為準；全部失敗 → `usage`：

1. `#N`：本工作區 journal 第 N 筆（1-based）。
2. file_id 前綴：長度 ≥ 4，且在目前版本的 `server.list()` 中唯一匹配。
3. 檔名：
   - 使用者指令（`cat`、`save`）：用 `client.list_files()` 找名稱完全相同者。**若 `list_files()` 拋 `IntegrityError`，該指令結果為 `rejected`**（這正是 V2 偵測植入／對調的方式）。同名多筆 → `usage`。
   - 攻擊指令：僅 V1 可用明文 `name` 比對 `server.list()`；V2 不可（攻擊者看不到檔名）。

使用者指令以 `#N` 或 ID 前綴指定時，直接呼叫 `client.download(fid)`，不經 `list_files()`。

### 3.5 journal（伺服器觀察到的上傳順序）

`root/<ver>/journal.json` 為 `file_id` 字串陣列，依「伺服器收到 put 的順序」記錄每次 `upload`/`upload-file`/`attack inject` 產生的新 ID。
理由：真實伺服器看得到請求順序，故 `#N` 不洩漏攻擊者本來不知道的資訊。journal 跨模擬器重啟保留（測試會驗證），`reset` 時一併刪除；`rollback` 不改 journal。

## 4. 紀錄檔（驗證證據）

- CLI 預設 → `logs/sim-YYYYmmdd-HHMMSS.log`（相對於目前工作目錄，資料夾不存在則建立）；`--log PATH` 指定；`--no-log` 不寫。函式介面中 `log_path=None` 表示不寫紀錄（CLI 才套預設路徑）。
- 每個非空、非註解指令寫入：
  ```
  [YYYY-mm-dd HH:MM:SS] sim(<ver 或 ->)> <指令原文，密碼遮蔽>
  <前綴> <text>
  ```
- **`login` 的密碼一律以 `****` 取代**，紀錄檔與腳本模式的回顯中不得出現密碼原文。
- 互動模式（v1.1 修訂）：一般指令以 `input()` 正常回顯；在 TTY 輸入 `login <v1|v2>`（不帶密碼）時，以 `getpass` 不回顯地詢問密碼後再執行。
- 顯示（v1.1 修訂）：`expect` 的結果只顯示 `[EXPECT 通過]`／`[EXPECT 失敗]`，不再加 `[成功]`；腳本模式空白行輸出空行、註解行原樣輸出。
- `cat` 判斷文字時，`\n`、`\t`、`\r` 都視為可顯示字元。
- 檔案以 UTF-8 寫入、每筆指令後 flush。

## 5. `MaliciousServer` 新增方法

```python
def snapshot(self, label: str) -> None:
    """把目前 files/ 與 meta/ 整份複製到 root/snapshots/<label>/（覆寫同名快照）。"""

def rollback(self, label: str) -> None:
    """以快照內容整份取代 files/ 與 meta/（快照後新增的檔案會消失）。快照不存在 → KeyError。"""
```

- `label` 必須符合 `server/storage.py` 的 `_check_id` 規則，否則 `ValueError`。
- 只操作伺服器自己的資料，不接收密碼或金鑰。
- 用途：示範 V2 的已知限制——伺服器整套回滾到舊狀態時，HMAC 清單仍然有效，**V2 無法偵測**（報告 Q5）。

## 6. CLI

```
python simulate.py [--root DIR] [--script FILE] [--log FILE | --no-log]
```

- 無 `--script`：互動模式，提示字元 `sim(<ver 或 ->)> `，讀到 EOF／`quit` 結束，回傳 0。
- `--script FILE`：逐行執行；`echo=True` 時每行先印 `sim(<ver>)> <指令>` 再印結果。
  結束碼：`failed` 或 `usage` 的總數 > 0 → 1，否則 0。（`rejected`/`error` 是預期中的展示結果，不算失敗。）
- 啟動時 `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`（若可用），避免 Windows 管線輸出中文時 `UnicodeEncodeError`。

## 7. 情境腳本（`scenarios/`，驗收材料）

| 檔案 | 內容 | 對應測試 |
|---|---|---|
| `01_v1_normal.sim` | V1 正常上傳、列出、下載 | T1 |
| `02_v1_attacks.sim` | V1 三種攻擊皆成功 | T3–T5 |
| `03_v2_attacks.sim` | V2 三種攻擊皆被拒絕 | T6–T8 |
| `04_wrong_password.sim` | V1/V2 密碼錯誤 | T2 |
| `05_v2_rollback.sim` | V2 回滾攻擊無法偵測（已知限制） | Q5 |
