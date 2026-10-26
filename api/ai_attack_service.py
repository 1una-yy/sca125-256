"""AES-128 neural-network side-channel evaluation service.

This module integrates the CNN/MLP evaluator from SCA-unified-api-main while
keeping TensorFlow optional. Models and datasets stay server-side; the browser
only selects a model family, leakage model, and benchmark dataset.
"""
from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
from pathlib import Path

import h5py
import numpy as np

from aes256_utils import AES_Sbox, hw_table

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
except Exception:
    pass

API_DIR = Path(__file__).resolve().parent
DEFAULT_AI_ROOT = API_DIR / "ai_assets"
DATASET_FILENAMES = {
    "fixed": "ASCAD.h5",
    "rand": "ascad-variable.h5",
    "ches": "ches_ctf.h5",
}
MODEL_FILENAMES = {
    ("cnn", "id", "fixed"): "fixed_cnn_bo_id_model.h5",
    ("cnn", "hw", "fixed"): "fixed_cnn_bo_hw_model.h5",
    ("mlp", "id", "fixed"): "fixed_mlp_bo_id_model.h5",
    ("mlp", "hw", "fixed"): "fixed_mlp_bo_hw_model.h5",
    ("cnn", "id", "rand"): "rand_cnn_bo_id_model.h5",
    ("cnn", "hw", "rand"): "rand_cnn_bo_hw_model.h5",
    ("mlp", "id", "rand"): "rand_mlp_bo_id_model.h5",
    ("mlp", "hw", "rand"): "rand_mlp_bo_hw_model.h5",
    ("cnn", "id", "ches"): "ches_cnn_bo_id_model.h5",
    ("cnn", "hw", "ches"): "ches_cnn_bo_hw_model.h5",
    ("mlp", "id", "ches"): "ches_mlp_bo_id_model.h5",
    ("mlp", "hw", "ches"): "ches_mlp_bo_hw_model.h5",
}
TARGET_BYTE_INDEX = {"fixed": 2, "rand": 2, "ches": 0}

# DPAv4 / ML-KEM：顯示訓練時已算好的固定結果（圖與數值由 build_ai_fixed_results.py 產生），
# 不需要 TensorFlow、原始 trace 或數百 MB 的模型 H5。
FIXED_RESULT_DIR = DEFAULT_AI_ROOT / "fixed_results"
FIXED_RESULT_DATASETS = {"dpav4": "AES-128 DPAv4", "mlkem": "ML-KEM"}
FIXED_RESULT_CHOICES = {
    (model_type, leakage_model, dataset_type)
    for model_type in ("cnn", "mlp")
    for leakage_model in ("id", "hw")
    for dataset_type in FIXED_RESULT_DATASETS
}


def _data_dir() -> Path:
    raw = os.getenv("SCA_AI_DATA_PATH", "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_AI_ROOT / "data"


def _model_dir() -> Path:
    raw = os.getenv("SCA_AI_MODEL_PATH", "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_AI_ROOT / "models"


def _max_traces() -> int:
    raw = os.getenv("SCA_AI_MAX_TRACES", "0").strip() or "0"
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("SCA_AI_MAX_TRACES 必須是 0 或正整數") from exc
    if value < 0:
        raise ValueError("SCA_AI_MAX_TRACES 不可小於 0")
    return value


def normalize_choice(model_type: str, leakage_model: str, dataset_type: str):
    choice = (
        str(model_type or "").strip().lower(),
        str(leakage_model or "").strip().lower(),
        str(dataset_type or "").strip().lower(),
    )
    if choice not in MODEL_FILENAMES and choice not in FIXED_RESULT_CHOICES:
        raise ValueError("AI 組合不正確：model_type 需為 cnn/mlp、leakage_model 需為 id/hw、dataset_type 需為 fixed/rand/ches/dpav4/mlkem")
    return choice


def _fixed_results() -> dict:
    path = FIXED_RESULT_DIR / "fixed_results.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _fixed_result_combinations() -> list:
    results = _fixed_results()
    combinations = []
    for model_type, leakage_model, dataset_type in sorted(FIXED_RESULT_CHOICES):
        combo_id = f"{model_type}-{leakage_model}-{dataset_type}"
        entry = results.get(combo_id)
        missing = []
        if entry is None:
            missing.append("fixed_results.json 內的 " + combo_id)
        else:
            missing += [name for name in (entry["ge_image"], entry["pearson_image"])
                        if not (FIXED_RESULT_DIR / name).is_file()]
        combinations.append({
            "id": combo_id,
            "model_type": model_type,
            "leakage_model": leakage_model,
            "dataset_type": dataset_type,
            "dataset_file": None,
            "model_file": entry["model_file"] if entry else None,
            "fixed_result": True,
            "ready": not missing,
            "missing": missing,
        })
    return combinations


def ai_service_status() -> dict:
    tensorflow_ready = importlib.util.find_spec("tensorflow") is not None
    sklearn_ready = importlib.util.find_spec("sklearn") is not None
    combinations = []
    data_dir, model_dir = _data_dir(), _model_dir()
    for (model_type, leakage_model, dataset_type), model_name in MODEL_FILENAMES.items():
        data_name = DATASET_FILENAMES[dataset_type]
        missing = []
        if not tensorflow_ready:
            missing.append("tensorflow")
        if not sklearn_ready:
            missing.append("scikit-learn")
        if not (data_dir / data_name).is_file():
            missing.append(data_name)
        if not (model_dir / model_name).is_file():
            missing.append(model_name)
        combinations.append({
            "id": f"{model_type}-{leakage_model}-{dataset_type}",
            "model_type": model_type,
            "leakage_model": leakage_model,
            "dataset_type": dataset_type,
            "dataset_file": data_name,
            "model_file": model_name,
            "ready": not missing,
            "missing": missing,
        })
    combinations += _fixed_result_combinations()
    return {
        "aes_bits": 128,
        "mode": "server_benchmark",
        "tensorflow_available": tensorflow_ready,
        "sklearn_available": sklearn_ready,
        "ready_any": any(item["ready"] for item in combinations),
        "max_traces": _max_traces(),
        "combinations": combinations,
    }


def validate_ai_request(model_type: str, leakage_model: str, dataset_type: str):
    choice = normalize_choice(model_type, leakage_model, dataset_type)
    status = ai_service_status()
    selected = next(item for item in status["combinations"] if (
        item["model_type"], item["leakage_model"], item["dataset_type"]
    ) == choice)
    if selected["missing"]:
        raise RuntimeError("AI 攻擊尚未就緒，缺少：" + "、".join(selected["missing"]))
    return choice


def _fit_scaler(profile_dataset, chunk_size: int = 2048):
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    total = int(profile_dataset.shape[0])
    if total < 2:
        raise ValueError("profiling traces 至少需要 2 條")
    for start in range(0, total, chunk_size):
        batch = np.asarray(profile_dataset[start:start + chunk_size], dtype=np.float32)
        if batch.ndim != 2:
            raise ValueError(f"profiling traces 必須是 2D，目前為 {batch.shape}")
        scaler.partial_fit(batch)
    return scaler


def _load_server_dataset(dataset_type: str):
    path = _data_dir() / DATASET_FILENAMES[dataset_type]
    limit = _max_traces()
    with h5py.File(path, "r") as handle:
        if dataset_type in ("fixed", "rand"):
            profile = handle["Profiling_traces/traces"]
            attack = handle["Attack_traces/traces"]
            metadata_ds = handle["Attack_traces/metadata"]
            count = min(int(attack.shape[0]), limit) if limit else int(attack.shape[0])
            scaler = _fit_scaler(profile)
            raw = np.asarray(attack[:count], dtype=np.float32)
            metadata = np.asarray(metadata_ds[:count])
            if not metadata.dtype.names or "plaintext" not in metadata.dtype.names or "key" not in metadata.dtype.names:
                raise ValueError("ASCAD metadata 必須包含 plaintext 與 key 欄位")
            byte_index = TARGET_BYTE_INDEX[dataset_type]
            plaintext_byte = np.asarray(metadata["plaintext"], dtype=np.uint8)[:, byte_index]
            key_bytes = np.asarray(metadata["key"], dtype=np.uint8)[:, byte_index]
        else:
            profile = handle["profiling_traces"]
            attack = handle["attacking_traces"]
            metadata_ds = handle["attacking_data"]
            count = min(int(attack.shape[0]), limit) if limit else int(attack.shape[0])
            scaler = _fit_scaler(profile)
            raw = np.asarray(attack[:count], dtype=np.float32)
            metadata = np.asarray(metadata_ds[:count])
            if metadata.ndim != 2 or metadata.shape[1] <= 32:
                raise ValueError(f"CHES attacking_data 格式不正確：{metadata.shape}")
            byte_index = 0
            plaintext_byte = np.asarray(metadata[:, 0], dtype=np.uint8)
            key_bytes = np.asarray(metadata[:, 32], dtype=np.uint8)

    if raw.ndim != 2 or raw.shape[0] < 1:
        raise ValueError(f"attack traces 必須是非空 2D array，目前為 {raw.shape}")
    if plaintext_byte.shape[0] != raw.shape[0]:
        raise ValueError("attack traces 與 plaintext metadata 筆數不一致")
    if not np.all(key_bytes == key_bytes[0]):
        raise ValueError("AI Guessing Entropy 需要 attack set 使用固定目標金鑰；目前 metadata 的目標 byte 並非固定")
    scaled = scaler.transform(raw).astype(np.float32, copy=False)
    return scaled, raw, plaintext_byte, int(key_bytes[0]), byte_index


def _figure_to_base64(fig) -> str:
    buffer = io.BytesIO()
    fig.savefig(buffer, format="png", dpi=120, bbox_inches="tight")
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode("ascii")


def _image_base64(name: str) -> str:
    return base64.b64encode((FIXED_RESULT_DIR / name).read_bytes()).decode("ascii")


def _run_fixed_result(model_type: str, leakage_model: str, dataset_type: str) -> dict:
    """回傳 DPAv4 / ML-KEM 訓練時已算好的 GE 與 Pearson 結果。"""
    entry = _fixed_results()[f"{model_type}-{leakage_model}-{dataset_type}"]
    is_mlkem = dataset_type == "mlkem"
    byte_index = entry["target_byte_index"]
    final_rank = entry["final_rank"]
    verified = final_rank == 0
    correct_hex = f"{entry['correct_value']:02x}"
    target_word = "message byte" if is_mlkem else "key byte"
    return {
        "algorithm": f"ai_{model_type}",
        # 平均 rank 為 0 代表每次攻擊排第一的都是正確值，才把它當成猜測結果。
        "key_hex": correct_hex if verified else "",
        "key_bytes": [entry["correct_value"]] if verified else [],
        "num_traces": entry["num_traces"],
        "trace_length": entry["trace_length"],
        "plot_base64": _image_base64(entry["ge_image"]),
        "extra_plots": [
            {"title": "Pearson 相關係數圖", "plot_base64": _image_base64(entry["pearson_image"])},
        ],
        "aes_bits": None if is_mlkem else 128,
        "ai_attack": True,
        "evaluation_mode": "fixed_result",
        "scheme": FIXED_RESULT_DATASETS[dataset_type],
        "target_kind": "message" if is_mlkem else "key",
        "model_type": model_type,
        "leakage_model": leakage_model,
        "dataset_type": dataset_type,
        "model_file": entry["model_file"],
        "label_definition": entry["label_definition"],
        "target_byte_index": byte_index,
        "correct_key_byte_hex": correct_hex,
        "key_byte_verified": verified,
        "guessing_entropy_attacks": entry["repetitions"],
        "final_correct_key_rank": final_rank,
        "rank_zero_at_trace": entry["rank_zero_at_trace"],
        "top_candidates": [],
        "pearson_peak_sample": entry["pearson_peak_sample"],
        "pearson_peak_value": entry["pearson_peak_value"],
        "saved_metrics": entry["saved_metrics"],
        "note": (
            f"此為訓練時已算好的固定結果，未重新執行模型推論；只評估第 {byte_index} 個 {target_word}，"
            + ("不是 AES 金鑰，也不代表已還原完整訊息。" if is_mlkem else "不代表已還原完整 16-byte 金鑰。")
        ),
    }


def run_ai_evaluation(model_type: str, leakage_model: str, dataset_type: str) -> dict:
    model_type, leakage_model, dataset_type = validate_ai_request(model_type, leakage_model, dataset_type)

    if dataset_type in FIXED_RESULT_DATASETS:
        return _run_fixed_result(model_type, leakage_model, dataset_type)

    from tensorflow.keras.models import load_model
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure

    scaled, raw, plaintext_byte, target_key, byte_index = _load_server_dataset(dataset_type)
    model_name = MODEL_FILENAMES[(model_type, leakage_model, dataset_type)]
    model = load_model(_model_dir() / model_name, compile=False)
    model_input = scaled[..., None] if model_type == "cnn" else scaled

    try:
        predictions = np.asarray(model.predict(model_input, verbose=0), dtype=np.float64)
    except Exception as exc:
        raise ValueError(
            f"模型輸入與資料 Trace 長度不相容：資料 shape {model_input.shape}；請確認模型是用相同資料集訓練"
        ) from exc

    expected_classes = 256 if leakage_model == "id" else 9
    if predictions.ndim != 2 or predictions.shape != (raw.shape[0], expected_classes):
        raise ValueError(
            f"模型輸出 shape 不正確：{predictions.shape}；{leakage_model.upper()} 模型應輸出 {expected_classes} 類"
        )
    if not np.isfinite(predictions).all() or np.any(predictions < 0):
        raise ValueError("模型預測含有 NaN、Infinity 或負機率")

    row_sums = predictions.sum(axis=1, keepdims=True)
    if np.any(row_sums <= 0):
        raise ValueError("模型至少有一筆預測的機率總和為 0")
    predictions = predictions / row_sums

    guesses = np.arange(256, dtype=np.uint8)
    intermediates = AES_Sbox[plaintext_byte[:, None] ^ guesses[None, :]]
    classes = intermediates if leakage_model == "id" else hw_table[intermediates]
    log_predictions = np.log(np.clip(predictions, 1e-12, 1.0))

    # Average guessing entropy over several shuffled attacks, matching the
    # AI-assistance project rather than depending on one arbitrary trace order.
    nb_attacks = 10
    total_traces = raw.shape[0]
    all_ranks = np.empty((nb_attacks, total_traces), dtype=np.float64)
    guess_history = np.empty(total_traces, dtype=np.uint8)
    cumulative = np.zeros(256, dtype=np.float64)
    rng = np.random.default_rng()
    for attack_index in range(nb_attacks):
        permutation = rng.permutation(total_traces)
        cumulative = np.zeros(256, dtype=np.float64)
        for index, trace_index in enumerate(permutation):
            cumulative += log_predictions[trace_index, classes[trace_index]]
            order = np.argsort(cumulative)[::-1]
            all_ranks[attack_index, index] = int(np.flatnonzero(order == target_key)[0])
            if attack_index == nb_attacks - 1:
                guess_history[index] = np.uint8(order[0])
    ranks = all_ranks.mean(axis=0)

    leakage = hw_table[AES_Sbox[plaintext_byte ^ np.uint8(target_key)]].astype(np.float64)
    centered_leakage = leakage - leakage.mean()
    centered_traces = raw.astype(np.float64) - raw.mean(axis=0, keepdims=True)
    numerator = centered_traces.T @ centered_leakage
    denominator = np.sqrt(np.sum(centered_traces ** 2, axis=0) * np.sum(centered_leakage ** 2))
    correlation = np.divide(numerator, denominator, out=np.zeros_like(numerator), where=denominator > 0)

    trace_axis = np.arange(1, raw.shape[0] + 1)
    fig = Figure(figsize=(11, 8), dpi=120)
    ax_ge, ax_corr = fig.subplots(2, 1)
    ax_ge.plot(trace_axis, ranks, color="#356ae6", linewidth=1.5)
    ax_ge.axhline(0, color="#dc2626", linestyle="--", linewidth=1)
    ax_ge.set_title(f"AES-128 Byte {byte_index} — Guessing Entropy ({model_type.upper()} / {leakage_model.upper()})")
    ax_ge.set_xlabel("Number of attack traces")
    ax_ge.set_ylabel("Correct-key rank")
    ax_ge.set_ylim(-5, 260)
    ax_ge.grid(True, linestyle=":", alpha=.5)
    ax_corr.plot(correlation, color="#d97706", linewidth=1.1)
    ax_corr.set_title("Pearson correlation using the known target byte")
    ax_corr.set_xlabel("Sample index")
    ax_corr.set_ylabel("Correlation")
    ax_corr.grid(True, linestyle=":", alpha=.5)
    fig.tight_layout()

    guessed_key = int(np.argmax(cumulative))
    zero_positions = np.flatnonzero(ranks < 1.0)
    top_order = np.argsort(cumulative)[::-1][:5]
    return {
        "algorithm": f"ai_{model_type}",
        "key_hex": f"{guessed_key:02x}",
        "key_bytes": [guessed_key],
        "num_traces": int(raw.shape[0]),
        "trace_length": int(raw.shape[1]),
        "plot_base64": _figure_to_base64(fig),
        "aes_bits": 128,
        "ai_attack": True,
        "evaluation_mode": "server_benchmark",
        "model_type": model_type,
        "leakage_model": leakage_model,
        "dataset_type": dataset_type,
        "model_file": model_name,
        "target_byte_index": byte_index,
        "correct_key_byte_hex": f"{target_key:02x}",
        "key_byte_verified": guessed_key == target_key,
        "guessing_entropy_attacks": nb_attacks,
        "final_correct_key_rank": round(float(ranks[-1]), 2),
        "rank_zero_at_trace": int(zero_positions[0] + 1) if zero_positions.size else None,
        "top_candidates": [f"{int(value):02x}" for value in top_order],
        "note": f"AI 模型只評估 AES-128 第 {byte_index} 個 key byte，不代表已還原完整 16-byte 金鑰。",
    }
