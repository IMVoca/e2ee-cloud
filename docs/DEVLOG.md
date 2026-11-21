# 開發與驗證紀錄：線下互動模擬器

分工：**Claude** 負責架構（規格、驗收測試、情境腳本）、程式碼審查與獨立驗收、報告與投影片；**Codex** 依規格撰寫實作程式碼。
實作者不得修改驗收材料；驗收者不採信實作者的自我回報，每一輪都獨立重跑。

## 每一輪的檔案

| 檔案 | 內容 |
|---|---|
| `devlog/round-NN-prompt.md` | Claude 交給 Codex 的派工單（原文） |
| `devlog/round-NN-start.txt` | 派工開始／結束時間 |
| `devlog/round-NN-codex-output.txt` | Codex 執行過程與回報（原文） |
| `devlog/round-NN-acceptance*.txt` | Claude 獨立重跑 pytest 與情境的輸出 |
| `devlog/round-NN-review.md` | Claude 的審查結論與退回項目 |

## 時間軸（2026-11-17）

| 輪次 | 時間 | 實作 | 驗收結果 | 退回／決策 |
|---|---|---|---|---|
| 0 架構 | 20:10 | Claude：`SIM_SPEC.md` v1.0、`tests/test_simulator.py`、`scenarios/*.sim` | 測試因尚無 `simulate.py` 而失敗（預期） | — |
| 1 | 20:10–20:19 | Codex：`simulate.py`、`snapshot/rollback` | 87 passed、情境全過 | R1 TTY 每行都隱藏輸入（規格語意不清）；R2 CRLF；R3–R5 顯示細節 |
| 2 | 20:23–20:28 | Codex：修正 R1–R5 | 89 passed；以 monkeypatch 模擬 TTY 驗證密碼路徑 | 驗證時發現 R6：英文撇號 `it's` 被當成引號 |
| 3 | 20:29–20:33 | Codex：停下並回報**規格 v1.2 有誤**（偶數撇號會被 shlex 靜默吃掉） | 1 failed / 89 passed | 架構決策 v1.3：自由文字不經 shlex |
| 4 | 20:34–20:39 | Codex：依 v1.3 分流 | **90 passed、情境 52/52 expect 通過** | 最終驗收通過，凍結 |

## 從這次流程學到的

- 規格的模糊處會被實作者「合理地」誤解（R1）：規格要寫到可以被測試判定的程度。
- 驗收測試同時也在測規格：第 3 輪 Codex 沒有為了過測試而繞路，而是指出規格本身錯了；這是「實作者不得改測試」帶來的好處。
- 驗收者自己的手動驗證仍然必要：R6 是在模擬 TTY 時順手輸入英文句子才發現的，原本的測試沒有覆蓋。

每一輪對應的 git commit 見 `git log main..feat/offline-simulator`。
