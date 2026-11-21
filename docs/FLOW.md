# E2EE 迷你雲端流程圖

以下依據目前的 [V1 客戶端](../v1/client.py)、[V2 客戶端](../v2/client.py) 與 [惡意伺服器](../server/malicious.py) 繪製；金鑰推導及儲存細節另核對 `common/kdf.py`、`common/record.py` 與 `server/storage.py`。

圖中 `fid = file_id.encode()`、`name_utf8 = name.encode("utf-8")`；`||` 表示位元組串接，`0x00` 是一個零位元組。二進位記錄欄位透過 `FileRecord.to_dict()` 轉為 Base64，讀取時由 `FileRecord.from_dict()` 還原。

## 1. 系統架構與信任邊界

這是同一個 Python 程式內的物件呼叫，並非已實作的網路服務。公開介面是呼叫約定，沒有額外的介面類別。`MaliciousServer` 繼承 `HonestServer`，未呼叫攻擊方法時沿用原本行為；密碼、主金鑰與檔案金鑰只在客戶端使用。

```mermaid
flowchart LR
    subgraph TRUSTED["可信任：客戶端"]
        V1["V1 Client<br/>明文檔名與未認證 CBC"]
        V2["V2 Client<br/>加密檔名、GCM 與 HMAC"]
    end
    subgraph UNTRUSTED["不可信任：伺服器與儲存"]
        API["Server 公開介面<br/>put / get / list<br/>put_meta / get_meta"]
        H["HonestServer"]
        M["MaliciousServer<br/>只修改儲存記錄"]
        F["root/files/&lt;file_id&gt;.json<br/>兩個版本的檔案記錄"]
        S["root/meta/salt.json<br/>salt 的 Base64 字串"]
        MF["root/meta/manifest.json<br/>V2 entries 與 HMAC"]
        API <--> H
        API <--> M
        M -. 繼承 .-> H
        H <--> F
        H <--> S
        H <--> MF
        M -->|攻擊時透過 get 與 put 改寫| F
    end
    V1 <-->|跨越信任邊界| API
    V2 <-->|跨越信任邊界| API
```

`root` 預設是 `storage`。`meta/salt` 與 `meta/manifest` 是介面使用的邏輯鍵，實際檔案都帶 `.json`；manifest 在 V2 上傳後才寫入。伺服器儲存的是包裝金鑰與密文，V1 的 `name` 仍為明文。

## 2. 金鑰階層

兩個建構子先讀取 `get_meta("salt")`；不存在時以 `new_salt()` 產生 16 bytes，存入 Base64 salt。建構子只推導金鑰，不驗證密碼是否正確。每次上傳都另產生一把 32-byte 檔案金鑰，沒有從主金鑰推導檔案金鑰。

```mermaid
flowchart TD
    P["password<br/>字串先轉 UTF-8"] --> KDF["PBKDF2-SHA256<br/>600000 次，輸出 32 bytes"]
    S["salt：16 bytes<br/>讀取伺服器或首次隨機產生"] --> KDF
    KDF --> KM["K_master：32 bytes"]
    subgraph V1KEYS["V1"]
        FK1["每檔 file_key<br/>os.urandom：32 bytes"]
        W1["AES-256-CBC 包裝 file_key<br/>無 padding<br/>wrapped_key = iv_w || 密文<br/>16 + 32 = 48 bytes"]
        C1["file_key 加密 PKCS7 內容<br/>AES-CBC，獨立隨機 IV"]
        FK1 --> W1
        FK1 --> C1
    end
    KM -->|包裝金鑰| W1
    subgraph V2KEYS["V2"]
        HK["三次獨立 HKDF-SHA256<br/>salt=None，length=32"]
        KW["K_wrap<br/>info = e2ee-cloud v2 wrap"]
        KN["K_name<br/>info = e2ee-cloud v2 name"]
        KC["K_mac<br/>info = e2ee-cloud v2 manifest"]
        FK2["每檔 file_key<br/>os.urandom：32 bytes"]
        W2["AES-GCM 包裝 file_key<br/>AAD = fid<br/>wrapped_key = n_w || 密文與 tag<br/>12 + 32 + 16 = 60 bytes"]
        N2["AES-GCM 加密檔名<br/>AAD = fid"]
        C2["AES-GCM 加密內容<br/>AAD = fid || 0x00 || name_utf8"]
        MAC["HMAC-SHA256<br/>認證 manifest entries"]
        HK --> KW --> W2
        HK --> KN --> N2
        HK --> KC --> MAC
        FK2 --> W2
        FK2 --> C2
    end
    KM --> HK
```

V1 的 `iv_w` 與內容 IV 各為 16 bytes。V2 的包裝、檔名、內容 nonce 各自獨立隨機產生，皆為 12 bytes；檔名欄位為 `b64e(n_n || 加密檔名與 tag)`。隨機位元組均來自 `os.urandom`。

## 3. V1 上傳與下載

下圖從建構完成後開始。V1 不驗證清單、版本、記錄 ID、檔名與內容的真實性；解密或 unpad 的例外直接往外傳，不轉為 `IntegrityError`。

```mermaid
sequenceDiagram
    participant U as 呼叫端
    participant C as V1 Client
    participant S as Server 公開介面
    U->>C: upload 傳入 name 與 data
    C->>C: new_file_id，隨機 file_key 32 bytes
    C->>C: 隨機 iv_w 與 iv，各 16 bytes
    C->>C: K_master 以 CBC 包裝 file_key，不加 padding
    Note right of C: wrapped_key = iv_w || 32-byte 密文
    C->>C: data 加上 PKCS7 padding
    C->>C: file_key 以 CBC 加密內容
    C->>S: put 記錄，version=1，name 為明文
    Note over C,S: 二進位欄位先轉為 Base64
    S-->>C: 寫入完成
    C-->>U: file_id
    U->>C: download 傳入 file_id
    C->>S: get 請求該 file_id
    S-->>C: 儲存的 JSON 記錄
    C->>C: FileRecord.from_dict 還原 Base64 欄位
    C->>C: 用 wrapped_key 前 16 bytes 作 IV，以 K_master 解包
    C->>C: 用 file_key 與 nonce_or_iv 解密內容
    C->>C: PKCS7 unpad
    C-->>U: 回傳解出的內容
    Note over U,C: 任何解密或格式錯誤直接拋出原始例外
    U->>C: list_files
    C->>S: list
    S-->>C: 所有記錄
    C-->>U: 只篩選 version=1，直接回傳 ID 與明文檔名
```

## 4. V2 上傳

**實際程式先包裝金鑰，再加密檔名**，下圖依此順序。`upload()` 只呼叫 `_read_manifest()`，沒有呼叫 `_check_listing()`，也不下載或驗證既有檔案內容。記錄先寫入，再寫 manifest，兩次寫入並非交易。

```mermaid
sequenceDiagram
    participant U as 呼叫端
    participant C as V2 Client
    participant S as Server 公開介面
    U->>C: upload 傳入 name 與 data
    C->>S: get_meta 讀取 manifest
    S-->>C: manifest 或 None
    alt manifest 為 None
        C->>C: entries 設為空清單
    else manifest 存在
        C->>C: 取 entries，建立 canonical JSON，驗證 HMAC
        C->>C: 驗證 entries 結構、排序與 ID 唯一性
    end
    Note right of C: 驗證失敗即 IntegrityError，停止上傳
    C->>C: new_file_id，建立 fid 與 name_utf8
    C->>C: 隨機 file_key 32 bytes
    C->>C: 隨機 n_w、n_n、nonce，各 12 bytes
    C->>C: K_wrap 以 GCM 包裝 file_key，AAD = fid
    C->>C: K_name 以 GCM 加密 name_utf8，AAD = fid
    Note right of C: name_field = Base64 的 n_n || 密文與 tag
    C->>C: file_key 以 GCM 加密 data
    Note right of C: 內容 AAD = fid || 0x00 || name_utf8
    C->>S: put 序列化記錄，version=2
    S-->>C: 記錄寫入完成
    C->>C: entries 加入 file_id 與 name_field，依 ID 排序
    C->>C: canonical JSON 計算 HMAC-SHA256，MAC 轉 Base64
    C->>S: put_meta 寫入 manifest 的 entries 與 mac
    S-->>C: manifest 寫入完成
    C-->>U: file_id
```

清單認證的位元組格式精確為：

```python
canonical = json.dumps(entries, separators=(",", ":"), sort_keys=True).encode()
```

`entries` 是依 `file_id` 排序的 `[[file_id, name_field], ...]`，其中 `name_field` 是記錄內原樣保存的加密檔名字串。

## 5. V2 下載驗證順序

以下判斷依 `download()`、`_read_manifest()`、`_decrypt_name()` 的實際執行順序排列。`or` 條件從左至右短路，因此版本、ID、清單成員資格，以及兩個長度檢查皆分開標示。`FileRecord.from_dict()` 會先解碼三個二進位欄位，之後才檢查版本與清單成員資格。

```mermaid
flowchart TD
    A["download：get_meta 讀取 manifest"] --> B{"manifest 是 None？"}
    A -->|JSON 解碼或可轉換的格式錯誤| ERR["拋出 IntegrityError"]
    B -->|是| EMPTY["entries = 空清單"]
    B -->|否| MAC{"取 entries、canonical JSON<br/>解碼 mac 並驗證 HMAC 成功？"}
    MAC -->|否| ERR
    MAC -->|是| SHAPE{"entries 是 list，且每項是<br/>含兩個字串的 list？"}
    SHAPE -->|否| ERR
    SHAPE -->|是| SORT{"entries 等於 sorted entries？"}
    SORT -->|否| ERR
    SORT -->|是| UNIQUE{"所有 file_id 唯一？"}
    UNIQUE -->|否| ERR
    UNIQUE -->|是| REC{"get 記錄與 FileRecord.from_dict 成功？<br/>依序解碼 wrapped_key、nonce_or_iv、ciphertext"}
    EMPTY --> REC
    REC -->|否| ERR
    REC -->|是| VER{"record.version 等於 2？"}
    VER -->|否| ERR
    VER -->|是| ID{"record.file_id 等於請求的 file_id？"}
    ID -->|否| ERR
    ID -->|是| MEMBER{"file_id 與 record.name 的配對<br/>存在 entries 中？"}
    MEMBER -->|否| ERR
    MEMBER -->|是| WL{"wrapped_key 長度等於 60？"}
    WL -->|否| ERR
    WL -->|是| NL{"nonce_or_iv 長度等於 12？"}
    NL -->|否| ERR
    NL -->|是| NB{"file_id.encode 與 name 的 Base64 解碼成功？"}
    NB -->|否| ERR
    NB -->|是| NLen{"解碼後的 name 長度至少 28？"}
    NLen -->|否| ERR
    NLen -->|是| NAME{"K_name 的 GCM 解密與驗證成功？<br/>前 12 bytes 作 nonce，AAD = fid"}
    NAME -->|否| ERR
    NAME -->|是| UTF{"解出的檔名是合法 UTF-8？"}
    UTF -->|否| ERR
    UTF -->|是| KEY{"K_wrap 的 GCM 解包與驗證成功？<br/>前 12 bytes 作 nonce，AAD = fid"}
    KEY -->|否| ERR
    KEY -->|是| DATA{"file_key 的 GCM 內容解密與驗證成功？<br/>AAD = fid || 0x00 || name_utf8"}
    DATA -->|否| ERR
    DATA -->|是| OK["回傳明文 bytes"]
```

`_integrity_checks()` 將 `InvalidTag`、`InvalidSignature`、`ValueError`、`KeyError`、`TypeError`、`AttributeError`、`IndexError` 轉成 `IntegrityError`；Base64、JSON 與 UTF-8 解碼錯誤也包含在這些類型內。程式主動拋出的 `IntegrityError` 直接傳出，並非捕捉所有可能的例外，例如作業系統的 I/O 錯誤不在此轉換清單內。

下載**不呼叫** `_check_listing()`，只檢查目標記錄與 manifest 的配對。相對地，`list_files()` 依序執行 `_read_manifest()`、`_check_listing()`、逐筆 `_decrypt_name()`；清單檢查先比較 version 2 記錄的 `(file_id, name)` 集合，再比較記錄數量，最後才解密檔名。它不解包金鑰，也不驗證內容密文。

## 6. 三種攻擊對照

以下各圖假設原始資料與 manifest 均有效、只單獨執行該項攻擊，且替換內容確實不同、交換的檔名也不同。三種方法都以 `get()` 或 `list()` 取得既有 JSON，再用 `put()` 寫回；**不持有密碼或金鑰，也不修改 manifest**。因此 V2 的 manifest HMAC 本身會先通過，接著才在圖示檢查點失敗。

### 6.1 竄改內容

`tamper_content()` 先確認位置非負、原文與替換文字等長。V1 還要求變更不跨越 16-byte 區塊；V2 的可修改範圍不包含最後 16-byte tag。無效參數會拋出 `ValueError`，不會寫回記錄。

```mermaid
flowchart TD
    A["tamper_content<br/>delta = original XOR replacement"] --> V{"記錄版本？"}
    V -->|V1| B{"block = position // 16<br/>是否為第一區塊？"}
    B -->|是| IV["修改 nonce_or_iv<br/>從 position % 16 起 XOR delta"]
    B -->|否| CT["修改前一密文區塊<br/>起點為 16 * 前一區塊索引 + 區塊內偏移"]
    IV --> O1["V1 攻擊成功<br/>Transfer $0100 變成 Transfer $9100<br/>其他內容不變"]
    CT --> O2["V1 攻擊成功<br/>目標明文精準改寫，前一區塊變亂碼<br/>後續區塊不變，未破壞 padding 時仍接受"]
    V -->|V2| G["修改 ciphertext<br/>從 position 起 XOR delta，保留原 tag"]
    G --> L["V2 list_files 成功<br/>ID 與加密檔名未改變<br/>不檢查內容，沒有偵測到攻擊"]
    G --> D["V2 download 拒絕<br/>最先失敗：最後的內容 AES-GCM 驗證<br/>InvalidTag 轉為 IntegrityError"]
```

V1 的 `list_files()` 不受密文修改影響。第一區塊例子的完整下載內容是 `Transfer $9100 to Alice. Approved by Bob.`；V2 下載時，清單成員資格、長度、檔名與金鑰驗證都先通過，最後才在內容驗證失敗。

### 6.2 植入檔案

```mermaid
flowchart TD
    A["inject_file<br/>指定來源用 get，否則取 list 第一筆"] --> B{"有可複製的來源？"}
    B -->|預設來源且清單為空| E["拋出 ValueError"]
    B -->|有| C["複製來源記錄<br/>以 new_file_id 換上新 ID"]
    C --> V{"來源記錄版本？"}
    V -->|V1| N1["name 改為傳入的名稱<br/>其餘欄位照抄，再 put"]
    N1 --> O["V1 攻擊成功<br/>清單出現 confession.txt<br/>下載內容為 real report"]
    V -->|V2| N2["保留來源的加密 name<br/>其餘欄位照抄，再 put"]
    N2 --> L["V2 list_files 拒絕<br/>最先失敗：_check_listing 的集合比較<br/>新 ID 配對不在 manifest，拋出 IntegrityError"]
    N2 --> D["V2 download 新 ID 時拒絕<br/>最先失敗：目標配對不在 entries<br/>直接拋出 IntegrityError"]
```

若指定的來源 ID 不存在，`get()` 會拋出 `KeyError`。V1 複製的包裝金鑰與密文仍能一起解密，且未綁定 ID。V2 在上述最先失敗的檢查點就停止，尚未執行檔名或包裝金鑰的 AAD 驗證；這些 GCM 資料也綁定原 ID，並不能直接移植到新 ID。

### 6.3 對調檔名

```mermaid
flowchart TD
    A["swap_names<br/>get 兩筆記錄，只交換 name，再分別 put<br/>ID、包裝金鑰、nonce 與內容密文都不變"] --> V{"客戶端版本？"}
    V -->|V1| L1["list_files 直接接受交換後的明文名稱<br/>a.txt 現在指向原本 B 的 ID"]
    L1 --> D1["V1 攻擊成功<br/>下載清單中的 a.txt<br/>得到 content of B"]
    V -->|V2| L2["V2 list_files 拒絕<br/>最先失敗：_check_listing 的集合比較<br/>ID 與加密檔名配對改變，拋出 IntegrityError"]
    V -->|V2| D2["V2 download 原 ID 時拒絕<br/>最先失敗：目標配對不在 entries<br/>直接拋出 IntegrityError"]
```

此攻擊未改變記錄數量；V2 清單仍因配對集合不同而失敗。下載時版本與 ID 檢查先通過，但檔名配對不在 manifest 中；程式在解密檔名前就已停止，不能將此情境的首次拒絕歸因於 GCM 的 AAD。

以上驗證沒有外部保存的最新版本狀態。伺服器若同時回傳一整套相符的舊 manifest 與舊記錄，V2 仍無法偵測 rollback。
