# 任務：模擬器第 4 輪（依規格 v1.3 修正自由文字斷詞）

你在第 3 輪正確指出：`it's Bob's plan` 不會讓 shlex 失敗，而是被靜默吃掉撇號。感謝回報，規格已改為 v1.3，
請見 `docs/SIM_SPEC.md` 第 3 節「自由文字例外（v1.3）」與審查 `docs/devlog/round-03-review.md`。

要求：
- 第一個字（`line.split()` 取得，不分大小寫）為 `upload` 或 `expect` 時，**不使用 shlex**，
  改用 `line.strip().split(maxsplit=2)`，第三段為逐字保留的原文（含撇號、引號、連續空白）。
- 其他指令維持原本 shlex 行為（引號未閉合 → usage）。
- 移除第 3 輪加入的「ValueError 時才改用 split()」寫法，改成上述明確分流。

限制：只改 `simulate.py`；不得修改 tests、scenarios、docs 及其他檔案；不要 git commit。
完成條件：`python -m pytest -q` 全數通過（90 項）；五個情境 `--script` 結束碼皆 0；回報 pytest 摘要行。
