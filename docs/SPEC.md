# 實作規格（v1.0）

本文件是 `v1/`、`v2/`、`server/malicious.py`、`bench.py`、`demo.py` 的實作依據。
**驗收標準 = `pytest` 全數通過**（`tests/test_functional.py`、`tests/test_attacks.py`）。
測試檔是規格的一部分，實作時不可修改測試。

已完成且不得更改介面的模組：`common/kdf.py`、`common/record.py`、`common/errors.py`、`server/storage.py`。

---

## 0. 共通規則

- 只用 `cryptography` 套件，不得自行實作區塊加密或 MAC。
- 所有隨機值用 `os.urandom`。
- 客戶端**不得快取檔案內容**：每次 `download` 都向 server 取資料。
- 客戶端只透過 `HonestServer` 的公開方法（`put/get/list/put_meta/get_meta`）存取伺服器。
- 建構子 `Client(server, password)`：
  - 讀 `server.get_meta("salt")`；若為 `None`，以 `new_salt()` 產生並 `put_meta("salt", {"salt": b64e(salt)})`。
  - 以 `derive_master_key(password, salt)` 得到主金鑰 `K_master`。
  - **建構子不得因密碼錯誤而拋例外**（驗證延後到 list/download）。
- `list_files()` 回傳 `list[tuple[file_id, plaintext_name]]`，順序不限；只包含該版本（`record["version"]`）的記錄。
- `upload(name, data)` 回傳客戶端以 `new_file_id()` 產生的 `file_id`。

## 1. V1（`v1/client.py`，故意有漏洞）

| 欄位 | 內容 |
|---|---|
| `file_key` | `os.urandom(32)` |
| `wrapped_key` | `iv_w(16) ‖ AES-256-CBC(K_master, file_key, iv_w)`，**不 padding**（32 bytes 剛好兩個區塊），共 48 bytes |
| `nonce_or_iv` | `iv(16)`，隨機 |
| `ciphertext` | `AES-256-CBC(file_key, PKCS7(data), iv)` |
| `name` | 明文檔名 |
| `version` | `1` |

- `list_files()`：直接相信 `server.list()`。
- `download()`：解包金鑰 → 解密 → unpad；解得出來就回傳，不做任何驗證。錯誤（例如 unpad 失敗）直接往外拋，不轉成 `IntegrityError`。

## 2. V2（`v2/client.py`，修正版）

### 2.1 子金鑰

由 `K_master` 以 HKDF-SHA256（salt=None, length=32）衍生，彼此獨立：

| 金鑰 | info |
|---|---|
| `K_wrap` | `b"e2ee-cloud v2 wrap"` |
| `K_name` | `b"e2ee-cloud v2 name"` |
| `K_mac` | `b"e2ee-cloud v2 manifest"` |

### 2.2 記錄格式

令 `fid = file_id.encode()`。

| 欄位 | 內容 |
|---|---|
| `file_key` | `os.urandom(32)` |
| `wrapped_key` | `n_w(12) ‖ AESGCM(K_wrap).encrypt(n_w, file_key, aad=fid)` |
| `name` | `b64e( n_n(12) ‖ AESGCM(K_name).encrypt(n_n, name_utf8, aad=fid) )` |
| `nonce_or_iv` | `n(12)`，隨機 |
| `ciphertext` | `AESGCM(file_key).encrypt(n, data, aad = fid ‖ 0x00 ‖ name_utf8)` |
| `version` | `2` |

### 2.3 檔案清單（manifest）

存在 `server.put_meta("manifest", {...})`：

```json
{ "entries": [[file_id, name_field], ...],   // 依 file_id 排序；name_field 為記錄中的加密檔名字串
  "mac": "base64( HMAC-SHA256(K_mac, canonical) )" }
```

`canonical = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()`

- `upload`：先 `put` 記錄，再更新 manifest（加入新項目、重算 MAC）。
- 首次使用（`get_meta("manifest")` 為 `None`）視為空清單。
- `list_files()`：
  1. 驗證 manifest MAC，失敗 → `IntegrityError`。
  2. 取 `server.list()` 中 version 2 的記錄，`{(file_id, name_field)}` 必須**完全等於** manifest 的集合，否則 → `IntegrityError`。
  3. 解密每個檔名（AAD = fid），失敗 → `IntegrityError`。
- `download(file_id)`：
  1. 驗證 manifest MAC，且 `(file_id, record["name"])` 必須在 manifest 中，否則 → `IntegrityError`。
  2. 解密檔名、解包 `file_key`、解密內容；任何 `InvalidTag` 或格式錯誤一律轉成 `IntegrityError`。
- 已知限制（不需處理，寫入報告 Q5）：伺服器回傳**舊版** manifest 與記錄（rollback）無法偵測。

## 3. 惡意伺服器（`server/malicious.py`）

`MaliciousServer(root)` 繼承 `HonestServer`，**建構子不接收密碼或金鑰**。未呼叫攻擊方法時行為與 `HonestServer` 完全相同。
三個攻擊方法直接修改已儲存的記錄（攻擊發生在「儲存中」）。

### 3.1 `tamper_content(file_id, position, original, replacement)`

已知明文竄改：攻擊者知道（或猜到）明文 `position` 起的內容是 `original`，想把它改成 `replacement`（等長）。
令 `delta = original XOR replacement`。

- **version 1（CBC 可塑性）**：設 `blk = position // 16`、`off = position % 16`（假設 `off + len(delta) <= 16`）。
  - `blk == 0`：把 `delta` XOR 進 `nonce_or_iv[off:]` → 第 0 區塊被精準改寫，**其他內容完全不變**。
  - `blk >= 1`：把 `delta` XOR 進 `ciphertext[(blk-1)*16 + off:]` → 第 `blk` 區塊被精準改寫，第 `blk-1` 區塊變亂碼。
- **version 2（GCM = CTR + tag）**：把 `delta` XOR 進 `ciphertext[position:]`（CTR 模式下明文會被精準改寫，但 tag 會失效）。

### 3.2 `inject_file(name, source_file_id=None) -> str`

伺服器拿不到金鑰，因此**複製一筆既有記錄**（預設為 `list()` 第一筆，或指定的 `source_file_id`）作為新檔案：

- 新 `file_id = new_file_id()`，其餘欄位照抄。
- version 1：`name` 改為參數 `name`（明文檔名可任意偽造）。
- version 2：`name` 保留原值（伺服器無法偽造加密檔名）。
- 回傳新的 `file_id`。沒有任何記錄可複製時拋 `ValueError`。

### 3.3 `swap_names(file_id_a, file_id_b)`

對調兩筆記錄的 `name` 欄位，其餘不動。

## 4. 效能量測（`bench.py`，T9）

```python
def benchmark(client_cls, root, size=10 * 1024**2, rounds=20) -> dict:
    """在 root 建立 HonestServer，用 client_cls 上傳＋下載 size bytes 的隨機資料 rounds 次。
    回傳 {"upload_avg_s": float, "download_avg_s": float}（不含 KDF 時間）。"""
```

`python bench.py` 對 V1、V2 各跑一次，印出對照表。

## 5. 展示程式（`demo.py`）

`python demo.py` 在暫存資料夾中依序執行並以表格輸出，1 分鐘內跑完：

1. **V1 正常**：上傳／下載、列出檔案 → 成功。
2. **V1 受攻擊**：竄改內容、植入檔案、對調檔名 → 每項顯示「攻擊成功」及證據（例如竄改後的內容）。
3. **V2 受攻擊**：同樣三種攻擊 → 每項顯示「偵測並拒絕（IntegrityError）」。

只用標準函式庫輸出表格，不加額外相依套件。
