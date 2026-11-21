# E2EE 迷你雲端與惡意伺服器攻擊重現

重現 Hofmann & Truong, "End-to-End Encrypted Cloud Storage in the Wild: A Broken Ecosystem"（ACM CCS 2024）
的核心主張：**只加密、不認證的雲端無法阻止惡意伺服器竄改或偽造檔案。**

- **V1**：AES-CBC，未認證，檔名明文 → 攻擊成功
- **V2**：AES-GCM + AAD 綁定 + 清單 HMAC → 攻擊全部被偵測

## 安裝與執行

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt

pytest                          # 執行全部測試
python demo.py                  # 一鍵展示（約 2 秒）
python bench.py                 # T9 效能對照
python simulate.py              # 線下互動模擬器（輸入 help 查看指令）
```

需要 Python 3.11 以上，不需網路。

## 目錄結構

```
common/kdf.py        密碼 → 主金鑰（PBKDF2-SHA256, 600k 次）
common/record.py     伺服器 JSON 記錄格式 FileRecord
common/errors.py     IntegrityError
server/storage.py    HonestServer：put / get / list / put_meta / get_meta
server/malicious.py  MaliciousServer：tamper_content / inject_file / swap_names
v1/client.py         未認證加密版客戶端
v2/client.py         認證加密版客戶端
tests/               pytest（T1–T9＋模擬器驗收，共 90 項）
demo.py              展示程式
simulate.py          線下互動模擬器（使用者／惡意伺服器雙角色、紀錄檔、expect 斷言）
scenarios/*.sim      五個可重跑的驗證情境
docs/GUIDE.md        操作指南
docs/SIM_SPEC.md     模擬器規格
docs/DEVLOG.md       開發與驗證紀錄（Claude 架構／驗收 × Codex 實作）
```

## 介面約定

- 客戶端只能透過 `HonestServer` 的公開方法存取伺服器，因此 `MaliciousServer` 可直接替換。
- 伺服器記錄是 `dict`（JSON）；客戶端用 `FileRecord.to_dict()` / `from_dict()` 轉換。
- `file_id` 由客戶端以 `new_file_id()` 產生。
- 使用者層級資料（KDF salt、V2 清單 HMAC）用 `put_meta(key, dict)` / `get_meta(key)` 存取。

## 攻擊手法說明

1. **竄改內容**：攻擊者知道或猜到部分明文後，計算原文與目標文字的 XOR 差值。V1 將差值寫入 IV，可精準修改第一區塊；寫入前一密文區塊則可修改後續區塊，但會破壞前一區塊。CBC 沒有認證，因此客戶端仍接受。V2 的 GCM 標籤會驗證失敗，拋出 `IntegrityError`。
2. **植入檔案**：伺服器複製既有加密記錄，換上新 ID；V1 還能任意改明文檔名。V1 直接相信清單，複製的檔案也可正常解密。V2 的 HMAC manifest 不包含新項目，因此列出或下載時都會拒絕；檔名與包裝金鑰的 AAD 也綁定原 ID，無法移植到新 ID。
3. **對調檔名**：伺服器交換兩筆記錄的 `name`，讓 V1 使用者開啟 a.txt 時收到原本 b.txt 的內容。V2 的 manifest 會偵測 ID 與加密檔名配對改變；加密檔名也以 ID 作 AAD，內容則以 `file_id || 0x00 || name_utf8` 作 AAD，驗證失敗即拒絕。

三種攻擊都只修改儲存的 JSON，不需要密碼或金鑰。V2 仍無法偵測伺服器同時回傳舊版 manifest 與對應記錄的 rollback。
