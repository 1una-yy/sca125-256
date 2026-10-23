"""Offline, fixed-dataset ML-KEM-768 NTT basemul CPA for the local lab site.

Only previously validated coefficient pairs 0..245 are exposed. Each request
recomputes a candidate ranking from the power traces and ciphertext-derived
public NTT input; the saved secret is consulted only after ranking.
"""

from __future__ import annotations

import base64
import configparser
import io
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


Q = 3329
SAMPLES = 24400
TRACE_COUNT = 300
ROOT = Path(os.getenv(
    "SCA_MLKEM_TRACE_ROOT",
    r"C:\Users\User\chipwhisperer\chipwhisperer\jupyter\user\traces",
))
CACHE = Path(__file__).with_name("mlkem_data")
_PREFIX = "CWLITEARM_MLKEM768_FULL_DOT_PAIR0_"

_DATASETS = {
    "baseline": {
        "label": "基準金鑰",
        "files": {
            0: "OFF0_300_20261014_110850_334681",
            23000: "OFF23000_300_20261014_231108_694935",
            45000: "OFF45000_300_20261015_001414_978477",
            67000: "OFF67000_300_20261015_014228_980825",
            89000: "OFF89000_300_20261015_021253_010053",
        },
    },
    "new_key": {
        "label": "獨立新金鑰",
        "files": {
            0: "OFF0_300_20261014_132056_264910",
            23000: "OFF23000_300_20261014_230139_047733",
            45000: "OFF45000_300_20261015_002005_292541",
            67000: "OFF67000_300_20261015_015251_841675",
            89000: "OFF89000_300_20261015_021948_961307",
        },
    },
}
PAIR_RANGES = ((0, 52, 0), (52, 102, 23000), (102, 150, 45000),
               (150, 198, 67000), (198, 246, 89000))
HW8 = np.array([int(i).bit_count() for i in range(256)], dtype=np.float32)
CANDIDATES = np.arange(Q, dtype=np.int64)


def project_path(dataset_id: str, offset: int) -> Path:
    if dataset_id not in _DATASETS or offset not in _DATASETS[dataset_id]["files"]:
        raise ValueError("未知的 ML-KEM 固定資料集或擷取區段")
    return ROOT / (_PREFIX + _DATASETS[dataset_id]["files"][offset] + ".cwp")


def public_cache_path(dataset_id: str) -> Path:
    if dataset_id not in _DATASETS:
        raise ValueError("未知的 ML-KEM 固定資料集")
    return CACHE / f"{dataset_id}_public_ntt.npy"


def _wave_path(project: Path) -> Path:
    cfg = configparser.ConfigParser()
    if not cfg.read(project, encoding="utf-8"):
        raise FileNotFoundError(project)
    relative = cfg["Trace Management"]["tracefile0"].replace("\\", "/")
    trace_cfg = project.parent / relative
    trace_meta = configparser.ConfigParser()
    if not trace_meta.read(trace_cfg, encoding="utf-8"):
        raise FileNotFoundError(trace_cfg)
    return trace_cfg.parent / (trace_meta["Trace Config"]["prefix"] + "traces.npy")


def offset_for_pair(pair_index: int) -> int:
    if not 0 <= pair_index < 246:
        raise ValueError("目前僅驗證全域 pair 0–245（共 492 個秘密 NTT 係數）")
    return next(offset for start, stop, offset in PAIR_RANGES if start <= pair_index < stop)


def expected_centers(pair_index: int) -> tuple[int, int]:
    offset_for_pair(pair_index)
    if pair_index < 128:
        local_pair, first_peak = pair_index, 377
    else:
        local_pair, first_peak = pair_index - 128, 59377
    first = first_peak + 920 * (local_pair // 2) + 444 * (local_pair % 2)
    return first, first + 140


def dataset_status() -> list[dict]:
    statuses = []
    for dataset_id, spec in _DATASETS.items():
        projects = [project_path(dataset_id, offset) for offset in spec["files"]]
        ready = public_cache_path(dataset_id).is_file() and all(
            p.is_file() and p.with_suffix(".npz").is_file() and _wave_path(p).is_file()
            for p in projects if p.is_file()
        ) and all(p.is_file() for p in projects)
        statuses.append({"id": dataset_id, "label": spec["label"], "ready": ready,
                         "trace_count": TRACE_COUNT, "samples": SAMPLES,
                         "validated_coefficients": 492,
                         "pair_min": 0, "pair_max": 245})
    return statuses


def _signed16(values):
    values = np.asarray(values, dtype=np.int64) & 0xFFFF
    return np.where(values >= 0x8000, values - 0x10000, values)


def _fqmul(a, b):
    product = np.asarray(a, dtype=np.int64) * np.asarray(b, dtype=np.int64)
    t = _signed16(_signed16(product) * -3327)
    return _signed16((product - t * Q) >> 16)


def _hw16(values):
    values = np.asarray(values, dtype=np.int64) & 0xFFFF
    return HW8[values & 0xFF] + HW8[(values >> 8) & 0xFF]


def _rank(waves, leakage, start: int, stop: int):
    if start < 0 or stop > waves.shape[1] or start >= stop:
        raise ValueError("CPA 時間窗超出目前擷取範圍")
    h = leakage.astype(np.float32, copy=True)
    h -= h.mean(axis=1, keepdims=True)
    h /= np.sqrt(np.sum(h * h, axis=1, keepdims=True)) + 1e-20
    t = np.asarray(waves[:, start:stop], dtype=np.float32).copy()
    t -= t.mean(axis=0, keepdims=True)
    t /= np.sqrt(np.sum(t * t, axis=0, keepdims=True)) + 1e-20
    correlation = np.abs(h @ t)
    scores = correlation.max(axis=1)
    order = np.argsort(scores)[::-1]
    winner = int(order[0])
    return {"scores": scores, "order": order, "winner": winner,
            "peak": int(correlation[winner].argmax()) + start,
            "winner_correlation": correlation[winner].copy(),
            "window": (start, stop)}


def _direct(waves, b0, start, stop):
    leakage = _hw16(_fqmul(CANDIDATES[:, None], b0[None, :]))
    return _rank(waves, leakage, start, stop)


def _combined_r1(waves, b0, b1, a0_guess, start, stop):
    known = _fqmul(a0_guess, b1)
    candidate = _fqmul(CANDIDATES[:, None], b0[None, :])
    leakage = _hw16(_signed16(known[None, :] + candidate))
    return _rank(waves, leakage, start, stop)


def _plot(rows, pair_index: int) -> str:
    fig, axes = plt.subplots(2, 2, figsize=(11, 6), constrained_layout=True)
    for i, row in enumerate(rows):
        attack = row.pop("_attack")
        axes[i, 0].plot(np.arange(Q), attack["scores"], color="#247c88", linewidth=.65)
        axes[i, 0].axvline(row["guess_mod_q"], color="#cb672c", linestyle="--")
        axes[i, 0].set(title=f'Coefficient {row["global_coefficient"]}: candidate ranking',
                       xlabel="Candidate mod 3329", ylabel="max |r|")
        start, stop = attack["window"]
        axes[i, 1].plot(np.arange(start, stop) + row["adc_offset"],
                        attack["winner_correlation"], color="#247c88")
        axes[i, 1].axvline(row["peak_sample"], color="#cb672c", linestyle="--")
        axes[i, 1].set(title=f'Winning candidate: sample {row["peak_sample"]}',
                       xlabel="Sample from Trigger", ylabel="|r|")
        for ax in axes[i]:
            ax.grid(alpha=.25)
    fig.suptitle(f"ML-KEM-768 basemul CPA, pair {pair_index}")
    stream = io.BytesIO()
    fig.savefig(stream, format="png", dpi=110)
    plt.close(fig)
    return base64.b64encode(stream.getvalue()).decode("ascii")


def analyze_pair(dataset_id: str, pair_index: int) -> dict:
    if dataset_id not in _DATASETS:
        raise ValueError("未知的 ML-KEM 固定資料集")
    pair_index = int(pair_index)
    offset = offset_for_pair(pair_index)
    project = project_path(dataset_id, offset)
    original = project_path(dataset_id, 0)
    cache = public_cache_path(dataset_id)
    if not project.is_file() or not cache.is_file():
        raise FileNotFoundError("ML-KEM 固定資料尚未準備完成；請先執行 prepare_mlkem_data.py")
    waves = np.load(_wave_path(project), mmap_mode="r", allow_pickle=False)
    if waves.shape == (TRACE_COUNT + 1, SAMPLES):
        # The native .npy has one unpaired final capture; the .cwp exposes 300.
        waves = waves[:TRACE_COUNT]
    public = np.load(cache, mmap_mode="r", allow_pickle=False)
    if waves.shape != (TRACE_COUNT, SAMPLES) or public.shape != (TRACE_COUNT, 3, 256):
        raise ValueError("ML-KEM Trace 或公開 NTT 輸入尺寸不符")
    with np.load(original.with_suffix(".npz"), allow_pickle=False) as first, \
         np.load(project.with_suffix(".npz"), allow_pickle=False) as current:
        if int(current["adc_offset"]) != offset or int(current["samples"]) != SAMPLES:
            raise ValueError("錄製 offset 或樣本長度與白名單不符")
        for name in ("keygen_coins", "secret_key", "encaps_coins", "ciphertexts"):
            if not np.array_equal(first[name], current[name]):
                raise ValueError(f"重播驗證失敗：{name} 不相符")
        if not np.array_equal(public[:, 0, :2], first["public_pairs"]):
            raise ValueError("公開 NTT 快取與錄製資料不相符")
        truth = np.array(current["secret_ntt"], copy=True)
    poly_index, local_pair = divmod(pair_index, 128)
    b0 = np.asarray(public[:, poly_index, 2 * local_pair], dtype=np.int64)
    b1 = np.asarray(public[:, poly_index, 2 * local_pair + 1], dtype=np.int64)
    rows = []
    centers = expected_centers(pair_index)
    for position, center in enumerate(centers):
        local = center - offset
        attack = _direct(waves, b0, local - 20, local + 21)
        model = "HW16(fqmul(a,b0))"
        if position == 1 and float(attack["scores"][attack["winner"]]) < .8:
            attack = _combined_r1(waves, b0, b1, rows[0]["guess_mod_q"],
                                  local, local + 61)
            model = "HW16(r1 combined)"
        coeff = 2 * pair_index + position
        actual = int(truth[poly_index, 2 * local_pair + position]) % Q
        order = attack["order"]
        winner = attack["winner"]
        peak = attack["peak"] + offset
        score = float(attack["scores"][winner])
        rows.append({"global_coefficient": coeff, "guess_mod_q": winner,
                     "truth_mod_q": actual,
                     "truth_rank": int(np.where(order == actual)[0][0]) + 1,
                     "correlation": score, "peak_sample": peak,
                     "expected_sample": center, "adc_offset": offset,
                     "model": model,
                     "verified": bool(winner == actual and score >= .8 and abs(peak - center) <= 3),
                     "top_candidates": [
                         {"value": int(k), "correlation": float(attack["scores"][k])}
                         for k in order[:5]],
                     "_attack": attack})
    plot = _plot(rows, pair_index)
    return {"dataset_id": dataset_id, "dataset_label": _DATASETS[dataset_id]["label"],
            "algorithm": "mlkem768_basemul_cpa", "pair_index": pair_index,
            "trace_count": TRACE_COUNT, "samples_per_trace": SAMPLES,
            "adc_offset": offset, "capture_interval": [offset, offset + SAMPLES - 1],
            "rows": rows, "verified_count": sum(row["verified"] for row in rows),
            "plot_base64": plot,
            "scope_note": "僅驗證目前錄製的 NTT 係數；未恢復完整 ML-KEM 私鑰。"}
