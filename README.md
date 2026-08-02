# AES-128 / AES-256 Side-Channel Attack Platform

以 FastAPI 與單頁網頁建置的晶片旁通道攻擊教學平台。支援 AES-128／AES-256 分析、攻擊進度與取消、AI 安全報告預覽，以及 PDF 下載。

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

## Windows 快速啟動

1. 下載或 clone 專案：

   ```powershell
   git clone https://github.com/1una-yy/sca125-256.git
   cd sca125-256
   ```

2. 雙擊根目錄的 `start_platform.bat`。

3. 啟動腳本會自動安裝 Python 套件、在 port `8000` 啟動 FastAPI，並開啟 `platform.html`。

4. 確認頁面右上角 API 位址為：

   ```text
   http://localhost:8000
   ```

常用網址：

- 操作頁面：http://localhost:8000/platform
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

## 設定 Gemini AI 報告

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

請勿把 `api/.env`、`api.env` 或真實 API key 提交至 Git。系統未設定 Gemini key 時，仍會產生固定格式的安全報告；量測事實、風險狀態與標準條文映射不會交由 AI 任意修改。

## 使用資料格式

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

模板必須來自與目標資料相同的晶片、韌體、時脈、trigger、探棒、取樣率與 Trace 長度。產生的 `api/templates/*.npz` 是硬體與量測環境專用檔，因此預設不提交 Git。詳細說明請見 [`api/templates/README.md`](api/templates/README.md)。

## AES-128 AI-CNN／AI-MLP 攻擊

這部分整合自 `SCA-unified-api-main`，採用伺服器 benchmark 模式：管理者預先準備 ASCAD／CHES 資料集與 TensorFlow 模型，使用者在網頁選擇 CNN 或 MLP、ID／HW 洩漏模型及資料集。

AI 套件需另外安裝：

```powershell
cd api
python -m pip install -r requirements-ai.txt
```

接著將資料集與模型放到 `api/ai_assets/data`、`api/ai_assets/models`，或在 `api/.env` 指定：

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
