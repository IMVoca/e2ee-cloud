# 任務：模擬器第 3 輪修正（驗收退回 R6）

`e2ee-cloud/simulate.py` 第 2 輪已通過驗收。驗收者在模擬 TTY 操作時發現新問題，審查原文見 `docs/devlog/round-02-review.md`，規格已更新為 `docs/SIM_SPEC.md` v1.2（第 3 節「斷詞」段落）。

R6：`upload a.txt it's ok` 因英文撇號被 shlex 判為「引號未閉合」而回 usage。
要求：斷詞失敗（ValueError）且第一個字（以空白切分取得、不分大小寫）為 `upload` 或 `expect` 時，改用 `line.split()`；其他指令維持 usage。
驗收測試：`tests/test_simulator.py::test_apostrophe_in_free_text`。

## 限制
- 只改 `simulate.py`，改動盡量小。**不得修改** `tests/`、`scenarios/`、`docs/` 及其他檔案。不要 git commit。

## 完成條件
- `python -m pytest -q` 全數通過（應為 90 項）；五個情境 `--script` 結束碼皆 0。回報修改摘要與 pytest 摘要行。
