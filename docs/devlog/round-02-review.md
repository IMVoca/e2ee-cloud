# Round 2 驗收審查（Claude）

- 時間：20:23 派工 → 20:27 Codex 完成 → 20:28 Claude 獨立驗收
- 修改範圍：僅 `simulate.py` ✅（受保護檔案 diff 為空）
- `pytest`：89 passed ✅；五個情境結束碼全 0、EXPECT 52 項全通過 ✅
- 紀錄檔密碼外洩 0 筆、`[成功] [EXPECT` 雙前綴 0 筆 ✅
- R1 TTY 密碼路徑：以 monkeypatch 模擬 TTY 驗證 —— 只在 `login v1` 時呼叫 `getpass("密碼：")`，含單引號與空白的密碼可正確登入，紀錄檔遮蔽 ✅
- R2–R5：皆已修正 ✅

## 新發現（退回第 3 輪）

| # | 嚴重度 | 問題 | 要求 |
|---|---|---|---|
| R6 | 中（可用性） | 上述 TTY 驗證中，`upload a.txt it's ok` 因英文撇號被 shlex 判為「引號未閉合」→ usage。屬規格 v1.0 選擇斷詞方式時的疏漏（架構方責任） | 斷詞失敗且指令為 `upload` 或 `expect` 時，改以空白切分（引號視為一般字元）；其他指令維持 usage。新增測試 `test_apostrophe_in_free_text` |
