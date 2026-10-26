"""Collect DPAv4 / ML-KEM AI fixed results into api/ai_assets/fixed_results.

The trained H5 files are several hundred MB, so the platform does not load
them at runtime. This script copies the already-rendered GE / Pearson figures
and extracts the numbers the web page needs into ``fixed_results.json``.

Usage (run inside the api folder):
    python build_ai_fixed_results.py "C:/path/to/AES256&mlkem"

The source folder must contain DPAV4/DPAV4 and mlkem/mlkem, each with the four
H5 files and a recreated_figures folder.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import h5py
import numpy as np

API_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = API_DIR / "ai_assets" / "fixed_results"

SPECS = {
    "dpav4": {
        "folder": Path("DPAV4") / "DPAV4",
        "group": "autosca_reproduction",
        "models": {
            ("cnn", "hw"): ("dpav4_cnn_hw_b0_relu_best.h5", "dpav4_cnn_hw_b0"),
            ("cnn", "id"): ("dpav4_cnn_id_b0_elu_best.h5", "dpav4_cnn_id_b0"),
            ("mlp", "hw"): ("dpav4_mlp_hw_b0_relu_best.h5", "dpav4_mlp_hw_b0"),
            ("mlp", "id"): ("dpav4_mlp_id_b0_elu_best.h5", "dpav4_mlp_id_b0"),
        },
        "ge_suffix": "_ge.png",
        "pearson_suffix": "_pearson.png",
    },
    "mlkem": {
        "folder": Path("mlkem") / "mlkem",
        "group": "plaintext_recovery",
        "models": {
            ("cnn", "hw"): ("mlkem_cnn_hw.h5", "mlkem_cnn_hw_replay"),
            ("cnn", "id"): ("mlkem_cnn_id.h5", "mlkem_cnn_id_replay"),
            ("mlp", "hw"): ("mlkem_mlp_hw.h5", "mlkem_mlp_hw_replay"),
            ("mlp", "id"): ("mlkem_mlp_id.h5", "mlkem_mlp_id_replay"),
        },
        "ge_suffix": "_ge_plaintext_rank.png",
        "pearson_suffix": "_pearson_training.png",
    },
}


def _text(value) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def _stable_zero_trace(curve: np.ndarray):
    """First trace count after which the average rank stays at 0."""
    above = np.flatnonzero(curve > 0.0)
    if above.size == 0:
        return 1
    if above[-1] + 1 >= curve.size:
        return None
    return int(above[-1] + 2)


def _summarise(dataset: str, h5_path: Path, group_name: str) -> dict:
    with h5py.File(h5_path, "r") as handle:
        group = handle[group_name]
        metrics = group["metrics"]
        if dataset == "dpav4":
            curve = np.asarray(metrics["ge_average"], dtype=np.float64)
            pearson = np.asarray(metrics["pearson_correlation"], dtype=np.float64)
            correct_value = int(group.attrs["correct_key"])
            repetitions = int(group.attrs["ge_attack_repetitions"])
        else:
            curve = np.asarray(metrics["plaintext_rank_curve"], dtype=np.float64)
            pearson = np.asarray(metrics["pearson_correlation_training"], dtype=np.float64)
            correct_value = int(np.asarray(group["data_roles/fixed_test_target_byte_values"]).reshape(-1)[0])
            repetitions = int(group.attrs["rank_curve_repetitions"])
        peak = int(np.argmax(np.abs(pearson)))
        return {
            "target_byte_index": int(group.attrs.get("target_byte", 0)),
            "correct_value": correct_value,
            "label_definition": _text(group.attrs.get("label_definition", "")),
            "repetitions": repetitions,
            "num_traces": int(curve.size),
            "trace_length": int(pearson.size),
            "final_rank": round(float(curve[-1]), 2),
            "min_rank": round(float(curve.min()), 2),
            "rank_zero_at_trace": _stable_zero_trace(curve),
            "pearson_peak_sample": peak,
            "pearson_peak_value": round(float(pearson[peak]), 4),
            "saved_metrics": {key: float(value) for key, value in metrics.attrs.items()},
        }


def main(source_root: Path) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = {}
    for dataset, spec in SPECS.items():
        folder = source_root / spec["folder"]
        for (model_type, leakage_model), (h5_name, figure_stem) in spec["models"].items():
            ge_png = folder / "recreated_figures" / (figure_stem + spec["ge_suffix"])
            pearson_png = folder / "recreated_figures" / (figure_stem + spec["pearson_suffix"])
            for path in (folder / h5_name, ge_png, pearson_png):
                if not path.is_file():
                    raise FileNotFoundError(path)
            shutil.copy2(ge_png, OUTPUT_DIR / ge_png.name)
            shutil.copy2(pearson_png, OUTPUT_DIR / pearson_png.name)
            entry = _summarise(dataset, folder / h5_name, spec["group"])
            entry.update({"model_file": h5_name, "ge_image": ge_png.name, "pearson_image": pearson_png.name})
            results[f"{model_type}-{leakage_model}-{dataset}"] = entry
            print(f"{model_type}-{leakage_model}-{dataset}: final rank {entry['final_rank']}")
    (OUTPUT_DIR / "fixed_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"已寫入 {OUTPUT_DIR}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("用法：python build_ai_fixed_results.py <AES256&mlkem 資料夾>")
    main(Path(sys.argv[1]))
