# 任務：實作線下互動模擬器（第 1 輪）

你在 Python 專案 `e2ee-cloud`（目前目錄）中工作。這是密碼學課程期末專題，重現論文
Hofmann & Truong, "End-to-End Encrypted Cloud Storage in the Wild" (CCS 2024) 的惡意伺服器攻擊。

## 必讀
1. `docs/SIM_SPEC.md` —— 本次任務的完整規格（權威來源）。
2. `tests/test_simulator.py` 與 `scenarios/*.sim` —— 驗收材料。
3. 既有程式：`server/storage.py`、`server/malicious.py`、`v1/client.py`、`v2/client.py`、`common/*`、`demo.py`（參考寫法）。

## 要做的事
- 新增 `simulate.py`，依 SIM_SPEC 第 2–4、6 節實作 `Result`、`Simulator`、`main`。
- 在 `server/malicious.py` 新增 `snapshot(label)` 與 `rollback(label)`（SIM_SPEC 第 5 節），既有三個方法不得改動。
- `.gitignore` 追加 `sim_storage/` 與 `logs/`。

## 硬性限制
- **不得修改** `tests/`、`scenarios/`、`docs/`、`common/`、`server/storage.py`、`v1/`、`v2/`、`demo.py`、`bench.py`。
- 只用標準函式庫與 `cryptography`，不得連網、不得安裝新套件。
- `Simulator.execute()` 永遠不往外拋例外。
- 程式碼註解與使用者可見訊息用繁體中文。程式要簡潔可讀（這份程式碼會出現在期末報告中）。
- 不要 git commit（由驗收者負責）。

## 完成條件
- `python -m pytest -q` 全數通過（既有 47 項 + 新的 test_simulator.py）。
- 對每個 `scenarios/*.sim` 執行 `python simulate.py --root <暫存資料夾> --script <檔> --no-log`，結束碼皆為 0。
- 完成後回報：修改／新增了哪些檔案、pytest 最後的摘要行、五個情境的結束碼。
