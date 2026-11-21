# 任務：模擬器第 2 輪修正（驗收退回）

在 `e2ee-cloud` 專案中，`simulate.py` 第 1 輪已通過功能驗收，但驗收審查發現以下問題。
規格已更新為 `docs/SIM_SPEC.md` v1.1（第 4 節新增三條「v1.1 修訂」），請依規格修正。
審查原文：`docs/devlog/round-01-review.md`。

| # | 問題 | 要求 |
|---|---|---|
| R1 | 互動模式在 TTY 下對每一行都用 `getpass`，使用者看不到自己輸入的指令 | 一般指令用 `input()` 正常回顯；只有在 TTY 輸入 `login <v1\|v2>`（不帶密碼）時，用 `getpass("密碼：")` 不回顯地詢問密碼，再組成完整指令交給 `execute()`。腳本模式與帶密碼的 login 行為不變（execute 收到 `login v1` 仍回 usage）。 |
| R2 | `cat` 把 CRLF 文字檔判為二進位 | `\r` 視為可顯示字元（測試 `test_cat_crlf_text_shown_as_text`）。 |
| R3 | expect 結果顯示 `[成功] [EXPECT 通過]` | expect 的結果只顯示 `[EXPECT 通過]`／`[EXPECT 失敗]`（測試 `test_expect_display_has_single_prefix`）。Result.status 不變。 |
| R4 | 腳本模式空白行印出空提示字元 | 空白行印空行；註解行原樣印出、不加提示字元。 |
| R5 | 互動模式無開場說明 | 啟動時印出一段開場：標題「E2EE 迷你雲端 — 線下互動模擬器」、`輸入 help 查看指令；login v1 不帶密碼可隱藏輸入`、工作區路徑、紀錄檔路徑（或「未啟用」）。 |

## 限制（同第 1 輪）
- 只改 `simulate.py`。**不得修改** `tests/`、`scenarios/`、`docs/` 及其他既有檔案。
- 不要 git commit。保持程式碼簡潔、繁體中文註解。

## 完成條件
- `python -m pytest -q` 全數通過（應為 89 項）。
- 五個 `scenarios/*.sim` 以 `--script` 執行，結束碼皆為 0。
- 回報修改摘要與 pytest 摘要行。
