"""Whitelisted server-side datasets for traditional SCA attacks."""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np


DEFAULT_ROOT = Path(
    r"C:\Users\User\OneDrive - 逢甲大學\桌面\專題"
    r"\Riscure Trace(AES256)-20260920T064528Z-1-004"
    r"\Riscure Trace(AES256)"
)
DATA_ROOT = Path(os.getenv("SCA_TRADITIONAL_DATA_ROOT", str(DEFAULT_ROOT)))
AES128_ROOT = Path(os.getenv(
    "SCA_AES128_TRACE_ROOT", r"C:\Users\User\SCA\SCA Trace&Code\traces"
))

FIVE_K_DIR = DATA_ROOT / "AES256固定金鑰(5000條)_1" / "website_upload"
LARGE_DIR = (
    DATA_ROOT
    / "AES固定金鑰(25000條)-20260922T053018Z-1-001"
    / "AES固定金鑰(25000條)"
    / "可上傳_npy_全時域降採樣4倍"
)

_DATASETS = {
    "aes128_100": {
        "label": "AES-128 固定金鑰・100 traces",
        "aes_bits": 128,
        "trace_count": 100,
        "trace_length": 5000,
        "traces_path": AES128_ROOT / "CWLITEARM_TINYAES128C_100_fixedkey_data" / "traces" / "2026.03.14-19.34.07_0traces.npy",
        "plaintexts_path": AES128_ROOT / "CWLITEARM_TINYAES128C_100_fixedkey_data" / "traces" / "2026.03.14-19.34.07_0textin.npy",
        "keylist_path": AES128_ROOT / "CWLITEARM_TINYAES128C_100_fixedkey_data" / "traces" / "2026.03.14-19.34.07_0keylist.npy",
        "extra_trace_position": "last",
    },
    "aes128_2000": {
        "label": "AES-128 固定金鑰・2,000 traces",
        "aes_bits": 128,
        "trace_count": 2000,
        "trace_length": 5000,
        "traces_path": AES128_ROOT / "CWLITEARM_TINYAES128C_2000_fixedkey_data" / "traces" / "2026.03.13-23.02.21_0traces.npy",
        "plaintexts_path": AES128_ROOT / "CWLITEARM_TINYAES128C_2000_fixedkey_data" / "traces" / "2026.03.13-23.02.21_0textin.npy",
        "keylist_path": AES128_ROOT / "CWLITEARM_TINYAES128C_2000_fixedkey_data" / "traces" / "2026.03.13-23.02.21_0keylist.npy",
        "extra_trace_position": "last",
    },
    "aes256_5000": {
        "label": "AES-256 固定金鑰・5,000 traces",
        "aes_bits": 256,
        "trace_count": 5000,
        "trace_length": 45000,
        "traces_path": FIVE_K_DIR / "traces.npy",
        "plaintexts_path": FIVE_K_DIR / "plaintexts.npy",
        "known_key_hex": "cafebabedeadbeef0001020304050607dabadabad00000c00001c0ffee55dead",
    },
    **{
        f"aes256_{count}": {
            "label": f"AES-256 固定金鑰・{count:,} traces",
            "aes_bits": 256,
            "trace_count": count,
            "trace_length": 11250,
            "traces_path": LARGE_DIR / f"traces_{count}_full_ds4.npy",
            "plaintexts_path": LARGE_DIR / f"plaintexts_{count}.npy",
        }
        for count in (10000, 15000, 20000)
    },
}


def get_dataset_spec(dataset_id: str) -> dict:
    try:
        return _DATASETS[dataset_id]
    except KeyError as exc:
        raise ValueError(f"未知的固定資料集：{dataset_id}") from exc


def dataset_status_list() -> list[dict]:
    statuses = []
    for dataset_id, spec in _DATASETS.items():
        pending = bool(spec.get("pending"))
        traces_path = spec.get("traces_path")
        plaintexts_path = spec.get("plaintexts_path")
        ready = bool(
            not pending
            and traces_path
            and plaintexts_path
            and Path(traces_path).is_file()
            and Path(plaintexts_path).is_file()
            and (not spec.get("keylist_path") or Path(spec["keylist_path"]).is_file())
        )
        statuses.append({
            "id": dataset_id,
            "label": spec["label"],
            "aes_bits": spec["aes_bits"],
            "trace_count": spec["trace_count"],
            "trace_length": spec["trace_length"],
            "ready": ready,
            "pending": pending,
            "has_known_key": bool(spec.get("known_key_hex") or spec.get("keylist_path")),
        })
    return statuses


def load_dataset(dataset_id: str, known_key_hex: str | None = None):
    spec = get_dataset_spec(dataset_id)
    traces_path = Path(spec["traces_path"])
    plaintexts_path = Path(spec["plaintexts_path"])
    if not traces_path.is_file() or not plaintexts_path.is_file():
        raise ValueError(f"固定資料集檔案不存在：{dataset_id}")

    traces = np.load(traces_path, mmap_mode="r", allow_pickle=False)
    plaintexts = np.load(plaintexts_path, mmap_mode="r", allow_pickle=False)
    if spec.get("extra_trace_position") == "last" and traces.shape[0] == plaintexts.shape[0] + 1:
        # These ChipWhisperer projects append one unpaired capture at the end.
        # The first N traces have been checked against their plaintexts by CPA.
        traces = traces[:plaintexts.shape[0]]
    if traces.ndim != 2 or plaintexts.shape != (traces.shape[0], 16):
        raise ValueError(
            f"固定資料集 shape 不正確：traces={traces.shape}, plaintexts={plaintexts.shape}"
        )
    if traces.shape != (spec["trace_count"], spec["trace_length"]):
        raise ValueError(f"固定資料集與預期尺寸不符：{dataset_id} traces={traces.shape}")

    recorded_key = None
    if spec.get("keylist_path"):
        keys = np.load(spec["keylist_path"], mmap_mode="r", allow_pickle=False)
        if keys.shape != (traces.shape[0], 16) or not np.all(keys == keys[0]):
            raise ValueError(f"{dataset_id} 的 keylist 不是固定 AES-128 金鑰")
        recorded_key = np.array(keys[0], dtype=np.uint8)

    normalized_key = "".join((known_key_hex or spec.get("known_key_hex") or "").split())
    known_key = None
    if normalized_key:
        expected_length = spec["aes_bits"] // 4
        if len(normalized_key) != expected_length:
            raise ValueError(f"AES-{spec['aes_bits']} known_key_hex 必須是 {expected_length} 個十六進位字元")
        try:
            known_key = np.frombuffer(bytes.fromhex(normalized_key), dtype=np.uint8).copy()
        except ValueError as exc:
            raise ValueError("known_key_hex 只能包含 0-9、a-f") from exc
    elif recorded_key is not None:
        known_key = recorded_key
    if recorded_key is not None and not np.array_equal(known_key, recorded_key):
        raise ValueError(f"{dataset_id} 提供的 known_key_hex 與錄製 keylist 不一致")
    return traces, plaintexts, known_key
