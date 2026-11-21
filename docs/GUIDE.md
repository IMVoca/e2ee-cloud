# 操作指南：E2EE 迷你雲端與線下互動模擬器

本指南給組員與助教使用：照著做就能在**完全離線**的情況下，親手重現「惡意伺服器竄改、植入、調換檔案」，並看到 V1 被騙、V2 擋下。

- 需要：Python 3.11 以上（Windows／macOS／Linux 皆可），不需網路、資料庫或帳號。
- 所有資料只寫在本機資料夾（預設 `sim_storage/`），隨時可刪。

---

## 1. 安裝（一次即可）

```bash
cd e2ee-cloud
python -m venv .venv
.venv\Scripts\activate            # macOS / Linux：source .venv/bin/activate
pip install -r requirements.txt   # 只有 cryptography 與 pytest
```

確認安裝成功：

```bash
python -m pytest -q
```

最後一行應為 `90 passed`（約 40 秒；其中 10 MB 效能測試最久）。

## 2. 三種使用方式

| 想做的事 | 指令 | 時間 |
|---|---|---|
| 一鍵看完整展示（錄 demo 影片用） | `python demo.py` | 約 2 秒 |
| 看 V1／V2 效能對照（T9） | `python bench.py` | 約 15 秒 |
| **自己動手操作攻擊** | `python simulate.py` | 自訂 |
| 重跑預先寫好的情境並留下紀錄 | `python simulate.py --script scenarios/02_v1_attacks.sim` | 每個約 2–5 秒 |

## 3. 互動模擬器快速上手（10 分鐘）

```bash
python simulate.py
```

畫面會顯示開場說明、工作區路徑與紀錄檔路徑（`logs/sim-日期-時間.log`）。提示字元 `sim(-)>` 中的 `-` 表示尚未登入；登入後會變成 `sim(v1)>` 或 `sim(v2)>`。

### 3.1 你會扮演兩個角色

| 角色 | 指令 | 說明 |
|---|---|---|
| 使用者（可信任的客戶端） | `login`、`upload`、`upload-file`、`ls`、`cat`、`save` | 經過 V1 或 V2 客戶端加解密 |
| 惡意伺服器（攻擊者） | `server ls`、`server show`、`server snapshot`、`attack …` | 只能碰伺服器上的 JSON，**拿不到密碼與金鑰** |

### 3.2 第一次操作：V1 被竄改金額

```text
sim(-)> login v1
密碼：                                   ← 不帶密碼時會隱藏輸入
sim(v1)> upload transfer.txt Transfer $0100 to Alice. Approved by Bob.
[成功] 已上傳 #1  c06ca5b6-…
sim(v1)> server show #1                   ← 伺服器看到的原始 JSON（密文已截短）
sim(v1)> attack tamper #1 10 0100 9100    ← 攻擊者：把位置 10 的 "0100" 改成 "9100"
[成功] 已修改欄位：
#1  c06ca5b6-…：nonce_or_iv               ← 只改了 IV
sim(v1)> cat transfer.txt
[成功] Transfer $9100 to Alice. Approved by Bob.   ← 使用者被騙了
```

### 3.3 同樣的攻擊換成 V2

```text
sim(v1)> login v2
密碼：
sim(v2)> upload transfer.txt Transfer $0100 to Alice. Approved by Bob.
sim(v2)> attack tamper #1 10 0100 9100
sim(v2)> cat transfer.txt
[偵測並拒絕] IntegrityError：檔案或清單驗證失敗
```

V1 與 V2 的資料放在不同工作區（`sim_storage/v1`、`sim_storage/v2`），互不影響。

### 3.4 另外兩種攻擊

```text
# 植入檔案：複製 #1 的密文，取名 confession.txt
sim(v1)> attack inject confession.txt #1
sim(v1)> ls                               ← V1：清單多了一個你沒上傳的檔案
sim(v2)> ls                               ← V2：[偵測並拒絕]（HMAC 清單對不上）

# 對調檔名
sim(v1)> upload a.txt content of A
sim(v1)> upload b.txt content of B
sim(v1)> attack swap a.txt b.txt          ← V1 檔名是明文，攻擊者可用檔名指定
sim(v1)> cat a.txt                        ← 拿到 content of B
# V2 攻擊者看不到檔名，只能用 #編號：attack swap #1 #2
```

### 3.5 V2 的已知限制：回滾

```text
sim(v2)> server snapshot before           ← 伺服器偷偷保存目前狀態
sim(v2)> upload invoice.txt pay 5000 by Friday
sim(v2)> attack rollback before           ← 整份換回舊狀態
sim(v2)> ls                               ← [成功]，但 invoice.txt 無聲消失
```

## 4. 指令參考

### 4.1 指定檔案（target）的方式

| 寫法 | 意義 | 誰能用 |
|---|---|---|
| `#3` | 伺服器收到的第 3 個檔案（上傳順序，伺服器本來就看得到） | 所有人 |
| `c06ca5b6` | 檔案 ID 前綴（至少 4 個字元、且唯一） | 所有人 |
| `a.txt` | 檔名 | 使用者指令皆可；攻擊指令只有 V1 可用（V2 檔名已加密） |

### 4.2 全部指令

| 指令 | 說明 |
|---|---|
| `login <v1\|v2> [password]` | 登入（不帶密碼則隱藏輸入）；可隨時重新登入換版本或換密碼 |
| `upload <name> <text...>` | 上傳一段文字 |
| `upload-file <path> [name]` | 上傳本機檔案（含空白的路徑請加引號） |
| `ls` | 列出檔案（V2 會先驗證 HMAC 清單） |
| `cat <target>` | 下載並顯示；二進位檔顯示大小與前 64 bytes 的 hex |
| `save <target> <path>` | 下載並存成本機檔案 |
| `server ls` | 伺服器視角的原始記錄列表 |
| `server show <target>` | 某筆記錄的原始 JSON |
| `server snapshot <label>` | 保存伺服器快照 |
| `attack tamper <target> <pos> <old> <new>` | 已知明文竄改（`old`、`new` 等長；V1 不可跨 16-byte 區塊） |
| `attack inject <fake_name> [source]` | 複製既有密文植入新檔案 |
| `attack swap <a> <b>` | 對調兩筆記錄的檔名欄位 |
| `attack rollback <label>` | 整份還原到快照 |
| `status` | 目前版本、工作區、記錄筆數、紀錄檔 |
| `reset <v1\|v2\|all>` | 清除工作區（只刪 `v1`、`v2` 子資料夾） |
| `expect ok\|rejected\|error` | 斷言上一個指令的結果狀態 |
| `expect contains\|not-contains <text>` | 斷言上一個指令的輸出是否包含某段文字 |
| `help`、`quit` | 說明、離開 |

### 4.3 結果標籤

| 標籤 | 意思 |
|---|---|
| `[成功]` | 指令完成。V1 被攻擊後的 `cat` 也會是成功 —— **這正是問題所在** |
| `[偵測並拒絕]` | V2 偵測到竄改，拋出 `IntegrityError` |
| `[錯誤]` | 其他錯誤，例如 V1 用錯密碼時解出無效 padding |
| `[指令錯誤]` | 打錯指令、尚未登入、找不到目標 |
| `[EXPECT 通過]`／`[EXPECT 失敗]` | 腳本斷言結果 |

## 5. 情境腳本與驗證紀錄

`scenarios/` 內有五個腳本，每段操作後都有 `expect` 斷言：

| 腳本 | 內容 |
|---|---|
| `01_v1_normal.sim` | V1 正常上傳、列出、下載（T1） |
| `02_v1_attacks.sim` | V1 三種攻擊皆成功（T3–T5） |
| `03_v2_attacks.sim` | V2 三種攻擊皆被拒絕（T6–T8） |
| `04_wrong_password.sim` | 密碼錯誤（T2） |
| `05_v2_rollback.sim` | V2 回滾攻擊無法偵測（Q5 限制） |

```bash
python simulate.py --script scenarios/03_v2_attacks.sim
echo %ERRORLEVEL%        # PowerShell：$LASTEXITCODE；macOS/Linux：echo $?
```

- 結束碼 `0` = 所有 expect 通過；`1` = 有 expect 失敗或指令打錯。
- 每次執行都會寫紀錄檔到 `logs/`（`--log 路徑` 自訂、`--no-log` 關閉）。紀錄檔含時間戳、指令與結果，**密碼一律顯示為 `****`**。
- 自己寫腳本：一行一個指令，`#` 開頭為註解。建議第一行寫 `reset all`，確保每次從乾淨狀態開始。

## 6. 重新產生期末報告

```bash
python ..\deliverables\build\build_report.py
```

腳本會實際執行 pytest、demo、bench 與五個情境，把輸出存到 `deliverables/evidence/`，填入報告模板後以 Edge 轉成 `deliverables/D6_期末報告_Group8.pdf`。報告中的所有數字都來自這次執行。

## 7. 常見問題

| 狀況 | 解法 |
|---|---|
| `ModuleNotFoundError: cryptography` | 沒啟用虛擬環境或沒安裝：重做第 1 節 |
| 中文變亂碼 | 改用 Windows Terminal；或先執行 `chcp 65001` |
| `login` 要等約 0.5 秒 | 正常：PBKDF2 跑 600,000 次，這是刻意的成本 |
| `[指令錯誤] 目標不存在或不唯一` | 先 `server ls` 看編號，改用 `#N` |
| V2 `ls` 一直被拒絕 | 攻擊留下的痕跡：`reset v2` 後重新 `login v2` |
| 想從頭來過 | `reset all`，或直接刪除 `sim_storage/` 資料夾 |
