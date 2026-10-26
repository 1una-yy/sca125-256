"""
main.py
AES-128 Side-Channel Attack API
啟動方式：uvicorn main:app --reload --host 0.0.0.0 --port 8000
API 文件：http://localhost:8000/docs

架構說明：
  - 所有攻擊演算法放在 attacks/ 資料夾
  - 新增演算法只需在 attacks/ 新增 .py 並繼承 BaseAttack，API 自動支援
  - 前端只需呼叫 POST /attack/{algorithm_id}，不需要因為加新演算法而改程式碼
"""

import importlib
import pkgutil
import os
import sys
import io
import asyncio
import base64
import binascii
import multiprocessing as mp
import queue as queue_module
import threading
import time
import uuid
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

import numpy as np
from fastapi import FastAPI, UploadFile, File, Form, Body, HTTPException
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# 確保 attacks/ 資料夾可以被 import
sys.path.insert(0, os.path.dirname(__file__))

from attack_base import registry, AttackInput
from trace_loader import load_traces, load_plaintexts
from report_service import generate_security_report, render_report_pdf, report_config
from template_store import build_template_model, save_template_model, template_status
from ai_attack_service import ai_service_status, run_ai_evaluation, validate_ai_request
from traditional_datasets import dataset_status_list, get_dataset_spec, load_dataset
from mlkem_cpa import analyze_pair as analyze_mlkem_pair, dataset_status as mlkem_dataset_status
from aes128_fixed_cpa import run_fixed_aes128_cpa

# ── 自動載入 attacks/ 資料夾下所有演算法模組 ──────────────────────────
import attacks
for _, module_name, _ in pkgutil.iter_modules(attacks.__path__):
    importlib.import_module(f"attacks.{module_name}")
# ─────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SCA Attack API",
    description="""
## AES-128 / AES-256 旁通道攻擊 API

**使用流程：**
1. `GET /algorithms` — 查詢目前支援的攻擊演算法清單
2. `POST /attack/{algorithm_id}` — 上傳 traces 與 plaintexts，執行攻擊

**支援上傳格式：** `.npy` / `.csv` / `.h5` / `.hdf5` / `.trs`

**AES-128 AI 攻擊：**
- 內建伺服器端 CNN / MLP 模型評估，支援 ASCAD Fixed、ASCAD Random、CHES CTF。
- AI 模型只評估資料集指定的單一 key byte，不宣稱還原完整 16-byte 金鑰。
- `GET /ai/status` 可檢查 TensorFlow、資料集與模型是否已就緒。

**新增演算法：**
- 在 `attacks/` 資料夾新增 .py 檔，繼承 `BaseAttack`，API 自動支援
    """,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # 正式環境請填前端網址
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


# ── 共用工具 ──────────────────────────────────────────────────────────

async def read_upload(file: UploadFile, field_name: str, is_plaintext: bool = False) -> np.ndarray:
    """讀取上傳檔案，自動依副檔名解析格式（npy/csv/h5/trs）"""
    try:
        content = await file.read()
        if is_plaintext:
            return load_plaintexts(content, file.filename or "file.npy")
        else:
            return load_traces(content, file.filename or "file.npy")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"{field_name} 解析失敗：{e}")


# ── Endpoints ─────────────────────────────────────────────────────────

# ── 可取消的攻擊工作 ───────────────────────────────────────────────────
_attack_jobs: dict[str, dict] = {}
_cancelled_job_ids: dict[str, float] = {}
_attack_jobs_lock = threading.Lock()


class AttackCancelledError(Exception):
    """使用者主動取消攻擊。"""


def _attack_process_worker(algorithm_id: str, data: AttackInput, output_queue):
    """在獨立程序執行 CPU 密集攻擊，讓主程序可以真正終止工作。"""
    try:
        attack = registry.get(algorithm_id)
        if attack is None:
            output_queue.put({"status": "error", "message": f"找不到演算法 '{algorithm_id}'"})
            return
        result = attack.run(data)
        output_queue.put({"status": "ok", "result": {
            "algorithm": result.algorithm,
            "key_hex": result.key_hex,
            "key_bytes": result.key_bytes,
            "num_traces": result.num_traces,
            "trace_length": result.trace_length,
            "plot_base64": result.plot_base64,
            **result.extra,
        }})
    except ValueError as exc:
        output_queue.put({"status": "value_error", "message": str(exc)})
    except Exception as exc:
        output_queue.put({"status": "error", "message": str(exc)})


def _dataset_attack_process_worker(
    algorithm_id: str,
    dataset_id: str,
    known_key_hex: str | None,
    output_queue,
):
    """Load a large fixed dataset inside the worker to avoid copying it from FastAPI."""
    try:
        traces, plaintexts, known_key = load_dataset(dataset_id, known_key_hex)
        data = AttackInput(
            traces=traces,
            plaintexts=plaintexts,
            known_key=known_key,
        )
        if algorithm_id == "cpa" and dataset_id in {"aes128_100", "aes128_2000"}:
            result = run_fixed_aes128_cpa(data)
            output_queue.put({"status": "ok", "result": {
                "algorithm": result.algorithm,
                "key_hex": result.key_hex,
                "key_bytes": result.key_bytes,
                "num_traces": result.num_traces,
                "trace_length": result.trace_length,
                "plot_base64": result.plot_base64,
                **result.extra,
            }})
        else:
            _attack_process_worker(algorithm_id, data, output_queue)
    except ValueError as exc:
        output_queue.put({"status": "value_error", "message": str(exc)})
    except Exception as exc:
        output_queue.put({"status": "error", "message": str(exc)})


async def _run_attack_process(
    job_id: str,
    algorithm_id: str,
    data: AttackInput | None = None,
    *,
    dataset_id: str | None = None,
    known_key_hex: str | None = None,
) -> dict:
    """啟動攻擊子程序並非阻塞等待；取消端點可 terminate 該程序。"""
    context = mp.get_context("spawn")
    output_queue = context.Queue(maxsize=1)
    if dataset_id:
        process = context.Process(
            target=_dataset_attack_process_worker,
            args=(algorithm_id, dataset_id, known_key_hex, output_queue),
            name=f"sca-dataset-{algorithm_id}-{job_id[:8]}",
            daemon=True,
        )
    else:
        if data is None:
            raise ValueError("缺少攻擊輸入資料")
        process = context.Process(
            target=_attack_process_worker,
            args=(algorithm_id, data, output_queue),
            name=f"sca-{algorithm_id}-{job_id[:8]}",
            daemon=True,
        )

    with _attack_jobs_lock:
        cutoff = time.monotonic() - 600
        for cancelled_id, created_at in list(_cancelled_job_ids.items()):
            if created_at < cutoff:
                _cancelled_job_ids.pop(cancelled_id, None)
        if job_id in _cancelled_job_ids:
            _cancelled_job_ids.pop(job_id, None)
            output_queue.close()
            raise AttackCancelledError()
        if job_id in _attack_jobs:
            output_queue.close()
            raise HTTPException(status_code=409, detail="相同 job_id 的攻擊正在執行")
        _attack_jobs[job_id] = {"process": process, "cancelled": False}
        try:
            process.start()
        except Exception:
            _attack_jobs.pop(job_id, None)
            output_queue.close()
            raise

    try:
        message = None
        while process.is_alive() and message is None:
            await asyncio.sleep(0.2)
            try:
                message = output_queue.get_nowait()
            except queue_module.Empty:
                pass
            with _attack_jobs_lock:
                job = _attack_jobs.get(job_id)
                if job and job["cancelled"]:
                    raise AttackCancelledError()

        await asyncio.to_thread(process.join, 0.5)
        with _attack_jobs_lock:
            job = _attack_jobs.get(job_id)
            if job and job["cancelled"]:
                raise AttackCancelledError()

        if message is None:
            try:
                message = await asyncio.to_thread(output_queue.get, True, 2.0)
            except queue_module.Empty as exc:
                raise RuntimeError(f"攻擊子程序未回傳結果（exit code: {process.exitcode}）") from exc

        if message.get("status") == "ok":
            return message["result"]
        if message.get("status") == "value_error":
            raise ValueError(message.get("message") or "攻擊輸入不正確")
        raise RuntimeError(message.get("message") or "攻擊子程序執行失敗")
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 2.0)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                await asyncio.to_thread(process.join, 1.0)
        with _attack_jobs_lock:
            _attack_jobs.pop(job_id, None)
        output_queue.close()
        output_queue.join_thread()

def _ai_process_worker(model_type: str, leakage_model: str, dataset_type: str, output_queue):
    """在獨立程序載入 TensorFlow 並執行 AES-128 AI 評估。"""
    try:
        result = run_ai_evaluation(model_type, leakage_model, dataset_type)
        output_queue.put({"status": "ok", "result": result})
    except ValueError as exc:
        output_queue.put({"status": "value_error", "message": str(exc)})
    except Exception as exc:
        output_queue.put({"status": "error", "message": str(exc)})


async def _run_ai_process(job_id: str, model_type: str, leakage_model: str, dataset_type: str) -> dict:
    """以可取消子程序執行 AI 評估，避免 TensorFlow 阻塞 FastAPI。"""
    context = mp.get_context("spawn")
    output_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_ai_process_worker,
        args=(model_type, leakage_model, dataset_type, output_queue),
        name=f"sca-ai-{model_type}-{job_id[:8]}",
        daemon=True,
    )

    with _attack_jobs_lock:
        cutoff = time.monotonic() - 600
        for cancelled_id, created_at in list(_cancelled_job_ids.items()):
            if created_at < cutoff:
                _cancelled_job_ids.pop(cancelled_id, None)
        if job_id in _cancelled_job_ids:
            _cancelled_job_ids.pop(job_id, None)
            output_queue.close()
            raise AttackCancelledError()
        if job_id in _attack_jobs:
            output_queue.close()
            raise HTTPException(status_code=409, detail="相同 job_id 的分析正在執行")
        _attack_jobs[job_id] = {"process": process, "cancelled": False, "kind": "ai"}
        try:
            process.start()
        except Exception:
            _attack_jobs.pop(job_id, None)
            output_queue.close()
            raise

    try:
        message = None
        while process.is_alive() and message is None:
            await asyncio.sleep(0.2)
            try:
                message = output_queue.get_nowait()
            except queue_module.Empty:
                pass
            with _attack_jobs_lock:
                job = _attack_jobs.get(job_id)
                if job and job["cancelled"]:
                    raise AttackCancelledError()

        await asyncio.to_thread(process.join, 0.5)
        with _attack_jobs_lock:
            job = _attack_jobs.get(job_id)
            if job and job["cancelled"]:
                raise AttackCancelledError()
        if message is None:
            try:
                message = await asyncio.to_thread(output_queue.get, True, 2.0)
            except queue_module.Empty as exc:
                raise RuntimeError(f"AI 子程序未回傳結果（exit code: {process.exitcode}）") from exc
        if message.get("status") == "ok":
            return message["result"]
        if message.get("status") == "value_error":
            raise ValueError(message.get("message") or "AI 評估輸入不正確")
        raise RuntimeError(message.get("message") or "AI 評估子程序執行失敗")
    finally:
        if process.is_alive():
            process.terminate()
            await asyncio.to_thread(process.join, 2.0)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                await asyncio.to_thread(process.join, 1.0)
        with _attack_jobs_lock:
            _attack_jobs.pop(job_id, None)
        output_queue.close()
        output_queue.join_thread()


class AIEvaluationRequest(BaseModel):
    model_type: str
    leakage_model: str
    dataset_type: str
    job_id: str | None = None

@app.get("/", summary="狀態確認")
def root():
    return {
        "status": "ok",
        "message": "AES-128 / AES-256 SCA Attack API 運行中",
        "platform": "/platform",
        \
    }


@app.get("/platform", include_in_schema=False)
@app.get("/platform.html", include_in_schema=False)
def platform_page():
    """由同一支 FastAPI 提供操作網頁，避免另外開啟本機 HTML。"""
    platform_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "platform.html")
    return FileResponse(platform_path, media_type="text/html; charset=utf-8")


@app.get("/mlkem", include_in_schema=False)
@app.get("/mlkem.html", include_in_schema=False)
def mlkem_page():
    """舊網址保留相容性，統一進入三演算法共用的操作頁。"""
    return RedirectResponse(url="/platform", status_code=307)


@app.get("/mlkem/datasets", summary="ML-KEM-768 已驗證固定 Trace 狀態")
def list_mlkem_datasets():
    return {"datasets": mlkem_dataset_status()}


class MLKEMPairRequest(BaseModel):
    dataset_id: str
    pair_index: int


@app.post("/mlkem/cpa", summary="執行單對 ML-KEM-768 NTT 係數 CPA")
async def run_mlkem_cpa(request: MLKEMPairRequest):
    try:
        return await asyncio.to_thread(analyze_mlkem_pair,
                                       request.dataset_id, request.pair_index)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get(
    "/algorithms",
    summary="取得支援的攻擊演算法清單",
    description="前端用來動態產生演算法選單，不需要寫死演算法名稱。",
)
def list_algorithms():
    return {"algorithms": registry.list_all()}


@app.get("/traditional-datasets", summary="傳統攻擊固定資料集狀態")
def list_traditional_datasets():
    return {"datasets": dataset_status_list()}


@app.post(
    "/attack/{algorithm_id}/fixed-dataset/{dataset_id}",
    summary="使用伺服器固定資料集執行傳統攻擊",
)
async def run_fixed_dataset_attack(
    algorithm_id: str,
    dataset_id: str,
    known_key_hex: str = Form(None),
    job_id: str = Form(None),
):
    attack = registry.get(algorithm_id)
    if attack is None:
        raise HTTPException(status_code=404, detail=f"找不到演算法 '{algorithm_id}'")
    if algorithm_id.startswith("ai_"):
        raise HTTPException(status_code=400, detail="固定傳統資料集不可使用 AI 攻擊端點")

    try:
        spec = get_dataset_spec(dataset_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    expected_aes_bits = 256 if algorithm_id.endswith("256") else 128
    if spec["aes_bits"] != expected_aes_bits:
        raise HTTPException(
            status_code=400,
            detail=f"{dataset_id} 是 AES-{spec['aes_bits']}，不可搭配 AES-{expected_aes_bits} 演算法",
        )

    active_job_id = (job_id or uuid.uuid4().hex).strip()
    if not active_job_id or len(active_job_id) > 100 or not all(
        ch.isalnum() or ch in "-_" for ch in active_job_id
    ):
        raise HTTPException(status_code=400, detail="job_id 只能包含英數字、-、_，且不可超過 100 字元")

    try:
        result_payload = await _run_attack_process(
            active_job_id,
            algorithm_id,
            dataset_id=dataset_id,
            known_key_hex=known_key_hex,
        )
    except AttackCancelledError:
        raise HTTPException(status_code=409, detail="攻擊已由使用者取消")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"固定資料集攻擊執行失敗：{exc}") from exc

    result_payload["dataset_id"] = dataset_id
    result_payload["dataset_label"] = spec["label"]
    return JSONResponse(result_payload)


@app.get("/template/status", summary="伺服器預建 Template Attack 狀態")
def get_template_status():
    """回傳 AES-128/AES-256 統計模板是否已由管理者建立。"""
    return {"templates": {"128": template_status(128), "256": template_status(256)}}

@app.post("/template/build-fixed/{aes_bits}", summary="以目前固定金鑰資料建立 Template")
async def build_fixed_template(
    aes_bits: int,
    traces_file: UploadFile = File(..., description="profiling traces"),
    plaintexts_file: UploadFile = File(..., description="profiling plaintexts"),
    known_key_hex: str = Form(..., description="固定 AES 金鑰"),
    poi_num: int = Form(10, description="每個 byte 的 POI 數"),
):
    """教學快速模式：用目前上傳資料與固定金鑰建立伺服器 Template。"""
    if aes_bits not in (128, 256):
        raise HTTPException(status_code=400, detail="aes_bits 必須是 128 或 256")
    normalized_key = "".join(known_key_hex.split())
    expected_hex_length = 32 if aes_bits == 128 else 64
    if len(normalized_key) != expected_hex_length:
        raise HTTPException(status_code=400, detail=f"AES-{aes_bits} 固定金鑰必須是 {expected_hex_length} 個十六進位字元")
    try:
        fixed_key = np.frombuffer(bytes.fromhex(normalized_key), dtype=np.uint8).copy()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="known_key_hex 只能包含 0-9、a-f") from exc
    traces = await read_upload(traces_file, "profiling_traces_file")
    plaintexts = await read_upload(plaintexts_file, "profiling_plaintexts_file", is_plaintext=True)
    if traces.shape[0] != plaintexts.shape[0]:
        raise HTTPException(status_code=400, detail=f"profiling traces 與 plaintexts 筆數必須一致：{traces.shape[0]}/{plaintexts.shape[0]}")
    keys = np.repeat(fixed_key[np.newaxis, :], traces.shape[0], axis=0)
    try:
        model = await asyncio.to_thread(build_template_model, aes_bits, traces, plaintexts, keys, poi_num)
        await asyncio.to_thread(save_template_model, model)
    except MemoryError as exc:
        raise HTTPException(status_code=507, detail="建立模板時記憶體不足，請減少 profiling traces 或先裁切 Trace 長度") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "ok", "message": f"AES-{aes_bits} profiling template 已建立", "template": template_status(aes_bits)}

@app.get("/ai/status", summary="AES-128 CNN / MLP 服務狀態")
def get_ai_status():
    """檢查 TensorFlow、伺服器資料集與預訓練模型組合。"""
    return ai_service_status()


@app.post("/ai/evaluate", summary="執行 AES-128 CNN / MLP 側信道評估")
async def evaluate_ai(request: AIEvaluationRequest):
    """使用伺服器端資料集與模型評估單一 AES-128 key byte。"""
    try:
        model_type, leakage_model, dataset_type = validate_ai_request(
            request.model_type, request.leakage_model, request.dataset_type
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    active_job_id = (request.job_id or uuid.uuid4().hex).strip()
    if not active_job_id or len(active_job_id) > 100 or not all(ch.isalnum() or ch in "-_" for ch in active_job_id):
        raise HTTPException(status_code=400, detail="job_id 只能包含英數字、-、_，且不可超過 100 字元")
    try:
        return await _run_ai_process(active_job_id, model_type, leakage_model, dataset_type)
    except AttackCancelledError:
        raise HTTPException(status_code=409, detail="AI 攻擊已由使用者取消")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI 攻擊執行失敗：{exc}") from exc

@app.post(
    "/attack/{algorithm_id}",
    summary="執行攻擊",
    description="""
執行指定演算法的旁通道攻擊。

**必填欄位：**
- `traces_file`：功耗波形 `.npy`，shape `(N, trace_length)`，dtype `float32/float64`
- `plaintexts_file`：明文 `.npy`，shape `(N, 16)`，dtype `uint8`

**選填欄位：**
- `preprocessed_traces_file`：如果之後有另外做前處理過的 traces，格式同 traces_file
  - 若提供，攻擊將使用此 traces 而非原始 traces
  - 不提供則直接用原始 traces（目前用不到這個欄位）

**回傳：**
```json
{
  "algorithm":    "cpa",
  "key_hex":      "2b7e151628aed2a6abf7158809cf4f3c",
  "key_bytes":    [43, 126, 21, 22, 40, 174, 210, 166, 171, 247, 21, 136, 9, 207, 79, 60],
  "num_traces":   2000,
  "trace_length": 24400,
  "plot_base64":  "<base64 PNG>"
}
```

前端顯示圖表：`<img src="data:image/png;base64,{plot_base64}" />`
""",
)
async def run_attack(
    algorithm_id: str,
    traces_file: UploadFile = File(..., description="功耗波形 .npy"),
    plaintexts_file: UploadFile = File(..., description="明文 .npy，shape (N, 16)"),
    preprocessed_traces_file: UploadFile = File(None, description="[選填，目前用不到] 前處理過的 traces .npy"),
    template_traces_file: UploadFile = File(None, description="[管理者／相容模式選填] 臨時 profiling traces .npy"),
    template_plaintexts_file: UploadFile = File(None, description="[管理者／相容模式選填] 臨時 profiling plaintexts .npy"),
    template_keys_file: UploadFile = File(None, description="[管理者／相容模式選填] 臨時 profiling keys .npy（AES-128: 16 bytes；AES-256: 32 bytes）"),
    known_key_hex: str = Form(None, description="[選填] 已知金鑰：AES-128 為 32 hex，AES-256 為 64 hex；SNR256 必填"),
    job_id: str = Form(None, description="[選填] 前端產生的工作 ID，供取消攻擊使用"),
):
    # 查詢演算法
    attack = registry.get(algorithm_id)
    if attack is None:
        available = [a["id"] for a in registry.list_all()]
        raise HTTPException(
            status_code=404,
            detail=f"找不到演算法 '{algorithm_id}'，目前支援：{available}"
        )

    # 讀取必填檔案（支援 npy / csv / h5 / trs）
    traces     = await read_upload(traces_file, "traces_file")
    plaintexts = await read_upload(plaintexts_file, "plaintexts_file", is_plaintext=True)

    # 選填：AI 前處理
    preprocessed = None
    if preprocessed_traces_file is not None:
        preprocessed = await read_upload(preprocessed_traces_file, "preprocessed_traces_file")

    # 管理者／相容模式選填：臨時 profiling 資料；一般使用者走伺服器預建模板
    tmpl_traces     = None
    tmpl_plaintexts = None
    tmpl_keys       = None
    if template_traces_file is not None:
        tmpl_traces     = await read_upload(template_traces_file, "template_traces_file")
    if template_plaintexts_file is not None:
        tmpl_plaintexts = await read_upload(template_plaintexts_file, "template_plaintexts_file", is_plaintext=True)
    if template_keys_file is not None:
        tmpl_keys       = await read_upload(template_keys_file, "template_keys_file", is_plaintext=True)

    known_key = None
    if known_key_hex:
        normalized_key = "".join(known_key_hex.split())
        if len(normalized_key) not in (32, 64):
            raise HTTPException(status_code=400, detail="known_key_hex 必須是 32 或 64 個十六進位字元")
        try:
            known_key = np.frombuffer(bytes.fromhex(normalized_key), dtype=np.uint8).copy()
        except ValueError:
            raise HTTPException(status_code=400, detail="known_key_hex 只能包含 0-9、a-f")

    # 組裝輸入並執行攻擊
    data = AttackInput(
        traces=traces,
        plaintexts=plaintexts,
        preprocessed_traces=preprocessed,
        template_traces=tmpl_traces,
        template_plaintexts=tmpl_plaintexts,
        template_keys=tmpl_keys,
        known_key=known_key,
    )

    active_job_id = (job_id or uuid.uuid4().hex).strip()
    if not active_job_id or len(active_job_id) > 100 or not all(ch.isalnum() or ch in "-_" for ch in active_job_id):
        raise HTTPException(status_code=400, detail="job_id 只能包含英數字、-、_，且不可超過 100 字元")

    try:
        result_payload = await _run_attack_process(active_job_id, algorithm_id, data)
    except AttackCancelledError:
        raise HTTPException(status_code=409, detail="攻擊已由使用者取消")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"攻擊執行失敗：{e}")

    return JSONResponse(result_payload)


@app.post("/attack/cancel/{job_id}", summary="取消正在執行的傳統或 AI 攻擊")
async def cancel_attack(job_id: str):
    """終止指定傳統或 AI 攻擊子程序，釋放 CPU/GPU 與記憶體。"""
    with _attack_jobs_lock:
        job = _attack_jobs.get(job_id)
        if job is None:
            cutoff = time.monotonic() - 600
            for cancelled_id, created_at in list(_cancelled_job_ids.items()):
                if created_at < cutoff:
                    _cancelled_job_ids.pop(cancelled_id, None)
            _cancelled_job_ids[job_id] = time.monotonic()
            return {"cancelled": True, "terminated": False, "status": "cancellation_registered", "job_id": job_id}
        job["cancelled"] = True
        process = job.get("process")

    terminated = False
    if process is not None and process.is_alive():
        process.terminate()
        await asyncio.to_thread(process.join, 2.0)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            await asyncio.to_thread(process.join, 1.0)
        terminated = not process.is_alive()

    return {"cancelled": True, "terminated": terminated, "status": "cancelled", "job_id": job_id}

@app.get("/report/config", summary="AI 報告服務狀態")
def get_report_config():
    """只回傳是否已設定金鑰，不會回傳或記錄 API key。"""
    return report_config()


@app.post("/report/generate", summary="產生 AI 輔助晶片旁通道安全分析報告")
def generate_report(payload: dict = Body(...)):
    """
    依分析結果產生可稽核的結構化報告。

    - 有 `GEMINI_API_KEY`：使用 Google Gemini API 產生敘述。
    - 無金鑰或 AI 暫時失敗：安全退回固定模板。
    - 量測事實、風險狀態及標準條文對照不交由 AI 改寫。
    """
    try:
        return JSONResponse(generate_security_report(payload))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"報告資料格式錯誤：{exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"報告產生失敗：{exc}") from exc


@app.post("/report/pdf", summary="下載晶片旁通道安全分析 PDF")
def download_report_pdf(payload: dict = Body(...)):
    report = payload.get("report")
    if not isinstance(report, dict):
        raise HTTPException(status_code=400, detail="payload.report 必須是已產生的報告物件")
    try:
        pdf_bytes = render_report_pdf(report, payload.get("plot_base64"))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF 產生失敗：{exc}") from exc

    document_id = str(report.get("document_id") or "SCA-Security-Report")
    safe_id = "".join(ch for ch in document_id if ch.isalnum() or ch in "-_") or "SCA-Security-Report"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_id}.pdf"'},
    )


class MessageItem(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[MessageItem]
    report_context: Optional[Dict] = None
    image_base64: Optional[str] = None
    image_mime_type: Optional[str] = "image/png"
    image_label: Optional[str] = None


class ChatResponse(BaseModel):
    content: str


def _tutor_system_prompt(report_context: Optional[Dict] = None) -> str:
    prompt = """你是旁通道攻擊分析平台的 AI 小助手，對象是第一次接觸旁通道攻擊的學生。請使用繁體中文。

回答規則：
- 先用一句話直接回答問題，再用條列或步驟把「為什麼」與「該怎麼做」講完整；一般 4 到 8 句，不要只丟一個結論。
- 使用者說「不懂」「沒有完整回答」時，換一個更白話的說法並舉例，不可重複上一次的句子。
- 有「目前分析背景」或附圖時，一定要引用其中的實際數字（例如猜中幾個 byte、正確值排名、trace 數）解釋本次結果，不可說你看不到畫面。
- 不要編造量測結果；單一 byte 不等於完整金鑰；資訊不足時說明還缺什麼。
- 畫面只顯示純文字：不要使用 Markdown 符號（如 **、#、`），條列請用「1.」或「・」開頭。

平台知識：
- 流程：1 選擇資料（上傳 Trace/Plaintext 或使用現有資料集）→ 2 選擇分析方法（CPA、DPA、MIA、SNR、Template、AI-CNN/MLP）→ 3 查看結果。
- 結果格子：綠色＝猜對、紅色＝猜錯、灰色＝沒有正確答案可比對；點一格可看該 byte 的分析圖。
- 排名（rank）：正確值在 256 個候選中的名次，0 代表排第一（猜中），數字越大越差。GE（Guessing Entropy）＝多次攻擊的平均排名，曲線降到 0 並維持住代表攻擊成功。
- CPA 圖：正確猜測會在洩漏時間點出現明顯最高的相關係數尖峰；尖峰不明顯通常是 trace 太少、未對齊或有雜訊／防護。
- AI 攻擊（CNN/MLP）只評估一個目標 byte。失敗常見原因：模型訓練用的裝置或資料與測試資料不同（可攜性問題）、trace 未對齊或有遮罩／隨機延遲、HW 標籤只有 9 類資訊較少、訓練資料不足或過擬合。
- DPAv4／ML-KEM 的 AI 結果是訓練時已算好的固定結果；ML-KEM 評估的是訊息（message）byte 的排名，不是 AES 金鑰，也不是破解私鑰。
- ML-KEM-768 CPA 每次只分析一組（2 個）NTT 係數，不代表整把私鑰被破解。"""
    if report_context:
        safe_context = {
            key: report_context.get(key)
            for key in (
                "attack_type", "dataset", "aes_version", "key_recovered", "snr",
                "num_traces", "trace_length", "elapsed_seconds", "selected_byte",
                "key_guess", "final_correct_key_rank", "image_label", "note",
                "result_summary", "correct_value", "rank_zero_at_trace", "evaluation_mode",
            )
            if key in report_context
        }
        prompt += "\n目前分析背景：" + json.dumps(safe_context, ensure_ascii=False)
    return prompt


def _tutor_generation_config(model: str) -> dict:
    # Gemini 3 的思考 token 也算在 maxOutputTokens 內；上限太小時回答會被截斷。
    config = {"maxOutputTokens": 4096, "temperature": 0.4}
    if model.startswith("gemini-3"):
        config["thinkingConfig"] = {"thinkingLevel": "low"}
    return config


def _call_tutor_gemini(request: ChatRequest) -> str:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("尚未設定 GEMINI_API_KEY；請在 api/.env 設定後重新啟動服務")

    model = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview").strip() or "gemini-3-flash-preview"
    model = model.removeprefix("models/")
    base_url = os.getenv(
        "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    ).rstrip("/")
    url = f"{base_url}/models/{urllib.parse.quote(model, safe='')}:generateContent?key={urllib.parse.quote(api_key, safe='')}"

    contents = []
    for message in request.messages[-10:]:
        text = message.content.strip()
        if not text:
            continue
        contents.append({
            "role": "user" if message.role == "user" else "model",
            "parts": [{"text": text[:8000]}],
        })
    if not contents:
        contents = [{"role": "user", "parts": [{"text": "請簡短介紹這個平台的使用方式。"}]}]

    if request.image_base64:
        image_data = request.image_base64.strip()
        if image_data.startswith("data:"):
            _, separator, image_data = image_data.partition(",")
            if not separator:
                raise RuntimeError("分析圖片的 Data URL 格式不正確")
        image_data = "".join(image_data.split())
        mime_type = (request.image_mime_type or "image/png").strip().lower()
        if mime_type not in {"image/png", "image/jpeg", "image/webp"}:
            raise RuntimeError("分析圖片格式只支援 PNG、JPEG 或 WebP")
        try:
            decoded_image = base64.b64decode(image_data, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("分析圖片不是有效的 Base64") from exc
        if not decoded_image:
            raise RuntimeError("分析圖片內容為空")
        if len(decoded_image) > 10 * 1024 * 1024:
            raise RuntimeError("分析圖片超過 10 MB，無法傳送給 AI")

        image_label = (request.image_label or "目前網頁顯示的攻擊分析圖")[:200]
        image_part = {
            "inline_data": {
                "mime_type": mime_type,
                "data": image_data,
            }
        }
        target_content = next(
            (content for content in reversed(contents) if content["role"] == "user"),
            None,
        )
        if target_content is None:
            target_content = {"role": "user", "parts": []}
            contents.append(target_content)
        target_content["parts"].append({"text": f"附圖名稱：{image_label}。請結合附圖與分析背景回答。"})
        target_content["parts"].append(image_part)

    system_prompt = _tutor_system_prompt(request.report_context)
    if request.image_base64:
        system_prompt += (
            "\n本次有附上平台目前顯示的分析圖。請辨識圖表類型，說明 X/Y 軸、"
            "主要峰值或趨勢、目前 Byte／金鑰猜測代表的意義及判讀限制；"
            "看不清楚的內容必須明確說明，不可臆測。"
        )

    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": _tutor_generation_config(model),
    }, ensure_ascii=False).encode("utf-8")
    http_request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    # Gemini 預覽版模型偶爾回 429/5xx 或逾時，屬暫時性錯誤，稍等後自動重試。
    attempts = 3
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(http_request, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code in (429, 500, 502, 503, 504) and attempt < attempts:
                time.sleep(2 * attempt)
                continue
            if exc.code in (429, 503):
                raise RuntimeError(
                    f"Gemini 伺服器暫時忙碌（{exc.code}），已重試 {attempts} 次仍失敗，請稍候 1 分鐘再問一次"
                ) from exc
            raise RuntimeError(f"Gemini API 回應 {exc.code}: {detail[:500]}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt < attempts:
                time.sleep(2 * attempt)
                continue
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(f"無法連線 Gemini API（已重試 {attempts} 次）：{reason}") from exc

    try:
        parts = payload["candidates"][0]["content"]["parts"]
        text = "".join(str(part.get("text", "")) for part in parts).strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("Gemini API 未回傳可顯示的文字") from exc
    if not text:
        raise RuntimeError("Gemini API 回傳空白內容")
    return text


@app.post("/api/ai/chat", response_model=ChatResponse, summary="AI 教學小助手")
async def ai_chat(request: ChatRequest):
    try:
        return ChatResponse(content=await asyncio.to_thread(_call_tutor_gemini, request))
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.get("/api/ai/health", summary="AI 教學小助手狀態")
def ai_chat_health():
    return {
        "status": "healthy" if os.getenv("GEMINI_API_KEY", "").strip() else "unconfigured",
        "api_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "service": "gemini",
        "model": os.getenv("GEMINI_MODEL", "gemini-3-flash-preview"),
    }

@app.get("/health", summary="Health check")
def health():
    ai_status = ai_service_status()
    return {"status": "ok", "ai_attacks": {"aes_bits": 128, "ready_any": ai_status["ready_any"]}}
