# AES-128 AI attack assets

AI-CNN / AI-MLP 沿用 `SCA-unified-api-main` 的伺服器 benchmark 模式。一般使用者不需要上傳模型；管理者需放置資料集與預訓練模型。

## 預設資料夾

```text
api/ai_assets/
├── data/
│   ├── ASCAD.h5
│   ├── ascad-variable.h5
│   └── ches_ctf.h5
└── models/
    ├── fixed_cnn_bo_id_model.h5
    ├── fixed_cnn_bo_hw_model.h5
    ├── fixed_mlp_bo_id_model.h5
    ├── fixed_mlp_bo_hw_model.h5
    ├── rand_cnn_bo_id_model.h5
    ├── rand_cnn_bo_hw_model.h5
    ├── rand_mlp_bo_id_model.h5
    ├── rand_mlp_bo_hw_model.h5
    ├── ches_cnn_bo_id_model.h5
    ├── ches_cnn_bo_hw_model.h5
    ├── ches_mlp_bo_id_model.h5
    └── ches_mlp_bo_hw_model.h5
```

也可在 `api/.env` 設定其他絕對路徑：

```dotenv
SCA_AI_DATA_PATH=C:/path/to/data
SCA_AI_MODEL_PATH=C:/path/to/models
SCA_AI_MAX_TRACES=2000
```

## 安裝 AI 套件

在 `api` 目錄執行：

```powershell
python -m pip install -r requirements-ai.txt
```

啟動後以 `GET /ai/status` 檢查每個模型／資料集組合。網頁只會在所選組合的 TensorFlow、dataset 與 model 都存在時開放執行。

## 分析範圍

- 僅 AES-128。
- ASCAD Fixed / Random 評估 byte index 2。
- CHES CTF 評估 byte index 0。
- 結果是單一 key byte 的 Guessing Entropy，不可描述為完整 16-byte AES 金鑰恢復。
- Attack set 的目標 key byte 必須固定；程式會拒絕混合不同目標 key 的資料。