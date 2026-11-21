# Round 3 驗收審查（Claude）

- 時間：20:29 派工 → 20:32 Codex 停下並提問 → 20:33 Claude 獨立驗收
- 結果：pytest **1 failed, 89 passed**（`test_apostrophe_in_free_text`）；五個情境仍全數通過
- Codex 的處置：沒有為了讓測試通過而繞過規格，而是指出**規格 v1.2 本身有誤**並請驗收者決定 ✅（正確行為）

## 根因（架構方責任）

v1.2 規定「shlex 斷詞**失敗**時才改用空白切分」。但 `it's Bob's plan` 有偶數個撇號，shlex 不會失敗，
而是把 `'s Bob'` 當成一對引號靜默吃掉，得到 `its Bobs plan`。驗收測試因此正確地失敗。

## 架構決策（v1.3）

`upload`、`expect` 兩個帶自由文字的指令**完全不經 shlex**，以 `line.strip().split(maxsplit=2)` 取「其餘原文」逐字保留。
取捨：`upload` 檔名不可含空白（`upload-file` 仍支援引號）。新增引號＋連續空白的斷言。退回第 4 輪。
