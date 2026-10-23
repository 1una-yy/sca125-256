@echo off
setlocal
title AES and ML-KEM SCA Platform

echo ========================================
echo   AES-128 / AES-256 / ML-KEM-768 SCA Platform
echo ========================================
echo.

cd /d "%~dp0api"

python --version >nul 2>&1
if errorlevel 1 goto no_python

echo [1/3] Checking Python packages...
python -c "import fastapi, uvicorn, numpy, matplotlib, scipy, h5py, reportlab, dotenv, sklearn" >nul 2>&1
if errorlevel 1 goto install_packages
goto packages_ready

:install_packages
echo Installing required packages...
python -m pip install -r requirements.txt
if errorlevel 1 goto package_error

:packages_ready
python -c "import tensorflow, sklearn" >nul 2>&1
if errorlevel 1 echo [NOTE] Optional AI packages are not installed. Run: python -m pip install -r requirements-ai.txt
if not errorlevel 1 echo [AI] TensorFlow and scikit-learn are ready.

echo [2/3] Starting FastAPI on port 8000...
start "SCA FastAPI Backend" /D "%~dp0api" cmd /k "python -m uvicorn main:app --host 127.0.0.1 --port 8000"

echo [3/3] Waiting for the server...
ping 127.0.0.1 -n 5 >nul
start "" "http://127.0.0.1:8000/platform"

echo.
echo Platform: http://127.0.0.1:8000/platform
echo ML-KEM CPA: select ML-KEM-768 on the platform page above
echo API docs: http://127.0.0.1:8000/docs
echo AI status: http://127.0.0.1:8000/ai/status
echo.
echo Keep the SCA FastAPI Backend window open while using the platform.
pause
exit /b 0

:no_python
echo [ERROR] Python was not found. Install Python 3.9 or later and add it to PATH.
pause
exit /b 1

:package_error
echo [ERROR] Required Python packages could not be installed.
pause
exit /b 1
