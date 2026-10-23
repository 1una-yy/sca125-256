# AES-128 / AES-256 Side-Channel Attack Platform

以 FastAPI 與網頁建置的晶片旁通道攻擊教學平台。支援 AES-128／AES-256 分析、ML-KEM-768 固定錄製資料的傳統 CPA、攻擊進度與取消、AI 安全報告預覽，以及 PDF 下載。

## 主要功能

- CPA（Correlation Power Analysis）
- DPA-DoM（Difference of Means）
- DPA-PCC（Pearson Correlation）
- MIA（Mutual Information Analysis）
- Template Attack（伺服器預建 profiling template）
- SNR 洩漏點／POI 分析
- AES-256 兩階段金鑰分析
- 執行時間預估、等待進度與取消運算
- Gemini API 輔助產生晶片安全分析報告
- 報告網頁預覽與 PDF 下載

> 本專案供教學、研究及已授權設備測試使用。請勿對未經授權的設備或資料執行攻擊。

## 環境需求

- Windows 10／11（建議使用內附的啟動腳本）
- Python 3.9 以上
- Chrome、Edge 或其他現代瀏覽器
- Gemini API key（選填；未設定時仍可使用固定格式報告）

## 新電腦安裝教學（第一次使用請照這裡做）

### 步驟 1：安裝 Python

到 https://www.python.org/downloads/ 下載 Python 3.9 以上（建議 3.11）。安裝時務必勾選 **Add Python to PATH**。

### 步驟 2：下載專案

```powershell
git clone https://github.com/1una-yy/sca125-256.git
cd sca125-256
```

沒有安裝 git 的話，也可以在本頁按 **Code → Download ZIP** 後解壓縮。

### 步驟 3：放入 AI 模型（選用，要用 AI-CNN／AI-MLP 才需要）

模型與 ASCAD／CHES 資料集檔案太大，沒有放在 GitHub，請向專案負責人索取 **`ai_assets.zip`**（約 1.3GB）。

1. 把 `ai_assets.zip` 解壓縮到專案的 `api` 資料夾裡。解完後的結構要像這樣：

   ```text
   sca125-256/
   └── api/
       └── ai_assets/
           ├── README.md
           ├── data/
           │   ├── ASCAD.h5
           │   ├── ascad-variable.h5
           │   └── ches_ctf.h5
           └── models/
               ├── fixed_cnn_bo_id_model.h5
               └── ...（共 10 個模型）
   ```

   請注意不要多包一層，例如 `api/ai_assets/ai_assets/data` 就是錯的。

2. 安裝 TensorFlow 等 AI 套件（只需要裝一次）：

   ```powershell
   cd api
   python -m pip install -r requirements-ai.txt
   ```

放在這個位置就不需要另外設定路徑。

### 步驟 4：設定 Gemini API key（選用，要用 AI 報告與小助手聊天才需要）

1. 到 https://aistudio.google.com/apikey 申請一組免費的 API key。
2. 把 `api/.env.example` 複製一份，改名為 `api/.env`：

   ```powershell
   Copy-Item api\.env.example api\.env
   ```

3. 用記事本打開 `api/.env`，在 `GEMINI_API_KEY=` 後面貼上你的 key。

沒有設定也可以使用平台，只是報告會改成固定格式，小助手只能回答固定問題。

### 步驟 5：啟動平台

雙擊根目錄的 `start_platform.bat`。腳本會自動安裝需要的 Python 套件、在 port `8000` 啟動後端，並開啟瀏覽器進入 http://127.0.0.1:8000/platform 。

使用期間請不要關掉 **`SCA FastAPI Backend`** 黑色視窗，關掉平台就會離線。

### 步驟 6：確認安裝成功

- http://127.0.0.1:8000/health：顯示 `status: ok` 代表後端正常。
- http://127.0.0.1:8000/ai/status：檢查 AI 模型是否都放對；缺哪個檔案會列在這裡。

### 新電腦上可以用的功能

| 功能 | 需要準備 |
|---|---|
| 上傳自己的 Traces／Plaintexts，執行 CPA、DPA-DoM、DPA-PCC、MIA、SNR | 不需要額外準備 |
| AES-256 Template Attack | 不需要額外準備，模板已內附於 repo |
| AES-128 AI-CNN／AI-MLP | 需要步驟 3 |
| AI 安全報告、教學小助手開放式聊天 | 需要步驟 4 |
| 報告預覽與 PDF 下載 | 不需要額外準備 |

以下功能在新電腦上**無法使用**：

- 「使用現有資料集」的 AES-128／AES-256／ML-KEM-768 固定資料：原始 trace 只存在原作者的電腦上。
- AES-128 Template Attack：尚未建立 AES-128 模板。
- CHES 資料集的 CNN-ID、MLP-ID 組合：缺少這兩個模型，CHES 請改選 HW。

常用網址：

- 操作頁面：http://localhost:8000/platform
- ML-KEM-768 CPA：在同一個操作頁面選擇「ML-KEM-768」
- API 健康狀態：http://localhost:8000/health
- API 文件：http://localhost:8000/docs
- 演算法清單：http://localhost:8000/algorithms

停止伺服器時，請在 `SCA FastAPI Backend` 視窗按 `Ctrl+C`，或關閉該後端視窗。只關閉啟動器視窗不會停止後端。

## 手動啟動

```powershell
cd api
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

後端顯示 `Uvicorn running on http://0.0.0.0:8000` 後，開啟：

```text
http://localhost:8000/platform
```

也可以直接開啟根目錄的 `platform.html`；此時 FastAPI 後端仍必須保持執行。

## 設定 Gemini AI 報告與教學小助手

1. 複製範例設定：

   ```powershell
   Copy-Item api\.env.example api\.env
   ```

2. 編輯 `api/.env`：

   ```dotenv
   GEMINI_API_KEY=你的_Gemini_API_Key
   GEMINI_MODEL=gemini-3-flash-preview
   ```

3. 重新啟動 FastAPI。

請勿把 `api/.env`、`api.env` 或真實 API key 提交至 Git。同一組設定同時供 AI 安全報告與頁面右下角的 AI 小助手使用；未設定 Gemini key 時，小助手會顯示設定提示，安全報告仍會產生固定格式的內容。量測事實、風險狀態與標準條文映射不會交由 AI 任意修改。

## 使用資料格式

### 伺服器固定資料集

第一步選擇「使用現有資料集」後，可分析 AES-128 固定金鑰資料（100 或 2,000 traces），以及 AES-256 固定資料（5,000、10,000、15,000 或 20,000 traces）。資料由後端以 memory-map 直接讀取，不會經由瀏覽器重新上傳。

AES-128 預設讀取 `C:/Users/User/SCA/SCA Trace&Code/traces`。若搬移資料，可用環境變數 `SCA_AES128_TRACE_ROOT` 指定新的 Trace 根目錄。原始 `.npy` 比明文多一條未配對的最後 Trace；後端只在這兩筆白名單資料中裁掉最後一條，並從固定的 `keylist.npy` 讀取實驗驗證金鑰，不修改原始資料。

預設資料根目錄已指向本機 Riscure AES-256 資料。若日後搬移資料，可在 `api/.env` 設定 `SCA_TRADITIONAL_DATA_ROOT` 覆寫根目錄。10,000／15,000／20,000 使用全時域降採樣 4 倍版本；5,000 使用完整 45,000 samples 版本。

### ML-KEM-768 傳統 CPA

開啟 `http://localhost:8000/platform`，選「使用現有資料集」→「ML-KEM-768」→「基準金鑰」或「獨立新金鑰」及全域 pair 0–245；下一步把 ML-KEM CPA 加入分析流程。每次分析一對相鄰的秘密 NTT 係數，結果會顯示猜測值、相關峰值、絕對取樣位置及保存真值的最終核對。已驗證範圍是 492/768 個秘密 NTT 係數，**不代表完整 ML-KEM 私鑰恢復**。目前 ML-KEM 只支援這兩組固定錄製，不接受 AES 格式的自行上傳檔案。

後端直接讀取原本的分段 `.cwp`/`.npz` 與 Trace `.npy`；`api/mlkem_data` 僅保存兩把金鑰各自從密文重建的**公開** NTT 輸入。若資料搬移或快取需要重建，設定 `SCA_MLKEM_TRACE_ROOT`、`SCA_MLKEM_NOTEBOOK_DIR` 後執行 `python api/prepare_mlkem_data.py`。這個一次性腳本沿用錄製專案的 PQClean 主機驗證程式，並核對板子保存的第 0 對公開係數。

AI 小助理的主程式採用使用者提供的 `ai-tutor.js`；ML-KEM 頁額外提供兩個固定常見問題。未設定 Gemini key 時，固定問題仍可使用，開放式聊天需要 API key。

使用者執行一般攻擊時，上傳：

- `Traces`：shape `(N, trace_length)`
- `Plaintexts / Text In`：shape `(N, 16)`，`uint8`

支援格式：

| 格式 | 說明 |
|---|---|
| `.npy` | NumPy array |
| `.csv` | 每列一筆資料 |
| `.h5` / `.hdf5` | HDF5 datasets |
| `.trs` | Riscure Inspector traces |

SNR 是洩漏點診斷，不是未知金鑰恢復攻擊，因此 AES-128 需要 32 個 hex 字元的已知金鑰，AES-256 需要 64 個 hex 字元。

## 預建 Template Attack 模板

一般使用者只上傳目標 `Traces` 與 `Plaintexts / Text In`。管理者必須事先用已知金鑰的 profiling 資料建立伺服器模板：

AES-128：

```powershell
cd api
python build_template.py --aes 128 --traces PROFILE_TRACES.npy --plaintexts PROFILE_TEXTIN.npy --keys PROFILE_KEYS.npy
```

AES-256：

```powershell
cd api
python build_template.py --aes 256 --traces PROFILE_TRACES.npy --plaintexts PROFILE_TEXTIN.npy --keys PROFILE_KEYS.npy
```

Profiling keys 格式：

- AES-128：`(N, 16)`
- AES-256：`(N, 32)`

模板必須來自與目標資料相同的晶片、韌體、時脈、trigger、探棒、取樣率與 Trace 長度。產生的 `api/templates/*.npz` 是硬體與量測環境專用檔，因此預設不提交 Git；唯一的例外是 repo 已內附的 `aes256_default.npz`。詳細說明請見 [`api/templates/README.md`](api/templates/README.md)。

## AES-128 AI-CNN／AI-MLP 攻擊

這部分整合自 `SCA-unified-api-main`，採用伺服器 benchmark 模式：管理者預先準備 ASCAD／CHES 資料集與 TensorFlow 模型，使用者在網頁選擇 CNN 或 MLP、ID／HW 洩漏模型及資料集。

AI 套件需另外安裝：

```powershell
cd api
python -m pip install -r requirements-ai.txt
```

接著將資料集與模型放到 `api/ai_assets/data`、`api/ai_assets/models`（直接解壓縮 `ai_assets.zip` 即可，見上方步驟 3），或在 `api/.env` 指定：

```dotenv
SCA_AI_DATA_PATH=C:/你的資料集資料夾
SCA_AI_MODEL_PATH=C:/你的模型資料夾
SCA_AI_MAX_TRACES=0
```

啟動後可開啟 http://localhost:8000/ai/status 檢查每個組合缺少哪些檔案。完整檔名與目錄結構請見 [`api/ai_assets/README.md`](api/ai_assets/README.md)。

注意：

- AI-CNN／AI-MLP 目前全部都是 AES-128。
- ASCAD 模型只評估 byte index 2；CHES CTF 評估 byte index 0。
- 網頁會顯示 Guessing Entropy、Pearson correlation、猜測 byte 與正確金鑰排名。
- 單一 byte 猜測正確不等於完整 16-byte AES-128 金鑰已還原。
- AI 運算也在獨立子程序執行，可用結果等待畫面的「取消分析」真正停止。
## API 演算法 ID

| AES-128 | AES-256 | 方法 |
|---|---|---|
| `cpa` | `cpa256` | CPA |
| `dpa_dom` | `dpa_dom256` | DPA Difference of Means |
| `dpa_pcc` | `dpa_pcc256` | DPA Pearson Correlation |
| `mia` | `mia256` | Mutual Information Analysis |
| `template` | `template256` | Template Attack |
| `snr` | `snr256` | SNR 洩漏點分析 |

更多端點與請求格式請參考 [`API_SPEC.md`](API_SPEC.md) 或啟動後的 `/docs`。

## 專案結構

```text
.
├── api/
│   ├── attacks/              # AES-128／AES-256 傳統攻擊模組
│   ├── ai_assets/            # 本機 AI dataset/model 放置說明
│   ├── ai_attack_service.py  # AES-128 CNN／MLP 評估服務
│   ├── templates/            # 預建模板說明與本機模型位置
│   ├── main.py               # FastAPI 入口
│   ├── report_service.py     # Gemini 與 PDF 報告服務
│   ├── build_template.py     # 離線 profiling template 建模工具
│   └── requirements.txt
├── platform.html             # 主要教學操作介面
├── API_SPEC.md               # API 串接文件
├── start_platform.bat        # Windows 快速啟動腳本
└── README.md
```

## 常見問題

### 頁面顯示「API 離線」

- 確認 FastAPI 視窗仍在執行。
- 開啟 http://localhost:8000/health，正常應顯示 `status: ok`。
- 確認平台右上角 API 位址是 `http://localhost:8000`。
- 修改程式後，先在後端視窗按 `Ctrl+C`，再重新執行啟動腳本。

### Template Attack 無法選擇

伺服器尚未建立對應 AES 版本的 profiling template。請由管理者執行 `build_template.py`，完成後重新啟動或重新整理平台。

### Port 8000 已被使用

先關閉舊的 `SCA FastAPI Backend` 視窗，或找出占用 port 8000 的舊程序後再重新啟動。
