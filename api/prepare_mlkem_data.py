"""One-time export of ciphertext-derived public NTT operands for the local site.

This reuses the already-tested PQClean host bridge from the recording project.
No secret is written to the derived cache and no waveform is copied.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np

from mlkem_cpa import _DATASETS, CACHE, project_path, public_cache_path


NOTEBOOK_DIR = Path(os.getenv(
    "SCA_MLKEM_NOTEBOOK_DIR",
    r"C:\Users\User\chipwhisperer\chipwhisperer\jupyter\user",
))
sys.path.insert(0, str(NOTEBOOK_DIR))
from mlkem768_public_inputs import pair_from_public_ntt, public_ntt_from_ciphertexts


def prepare() -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    for dataset_id in _DATASETS:
        sidecar = project_path(dataset_id, 0).with_suffix(".npz")
        with np.load(sidecar, allow_pickle=False) as data:
            public = public_ntt_from_ciphertexts(data["ciphertexts"])
            if not np.array_equal(pair_from_public_ntt(public, 0), data["public_pairs"]):
                raise ValueError(f"{dataset_id}: PQClean 公開 NTT 重建與板子紀錄不同")
        output = public_cache_path(dataset_id)
        np.save(output, public, allow_pickle=False)
        print(f"{dataset_id}: {public.shape} {public.dtype} -> {output}")


if __name__ == "__main__":
    prepare()
