@echo off
chcp 65001 >nul
title AES-128 / AES-256 SCA Platform Launcher

echo ========================================
echo   AES-128 / AES-256 SCA Platform
echo ========================================
echo.

cd /d "%~dp0api"

python --version >nul 2>&1
if errorlevel 1 (
    echo [錯誤] 找不到 Python，請先安裝 Python 3.9+
    pause
    exit /b 1
)

echo [1/3] 檢查 / 安裝相依套件...
python -m pip install -q -r requirements.txt
if errorlevel 1 (
    echo [錯誤] Python 相依套件安裝失敗
    pause
    exit /b 1
)

python -c "import tensorflow, sklearn" >nul 2>&1
if errorlevel 1 (
    echo [提示] AES-128 AI-CNN / AI-MLP 尚未安裝完整套件。
    echo        如需 AI 攻擊，請執行：python -m pip install -r requirements-ai.txt
) else (
    echo [AI] TensorFlow / scikit-learn 已就緒；模型與資料集狀態可在網頁查看。
)

echo [2/3] 啟動 FastAPI 後端 (port 8000)...
start "SCA FastAPI Backend" cmd /k "cd /d ""%~dp0api"" && python -m uvicorn main:app --host 0.0.0.0 --port 8000"

echo [3/3] 等待伺服器啟動...
timeout /t 4 /nobreak >nul

start "" "%~dp0platform.html"

echo.
echo ========================================
echo   操作網頁：%~dp0platform.html
echo   API 文件：http://localhost:8000/docs
echo   演算法清單：http://localhost:8000/algorithms
echo   AI 狀態：http://localhost:8000/ai/status
echo ========================================
echo.
echo AES-128 ID: cpa dpa_dom dpa_pcc mia template snr
echo AES-128 AI: ai_cnn ai_mlp
echo AES-256 ID: cpa256 dpa_dom256 dpa_pcc256 mia256 template256 snr256
echo.
echo 關閉本視窗不會關閉伺服器。
echo 要停止伺服器，請關閉 SCA FastAPI Backend 視窗。
echo.
pause