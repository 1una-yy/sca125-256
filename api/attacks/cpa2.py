"""
attacks/cpa.py
CPA（相關電力分析）攻擊模組 — AES-256 完整版。

兩階段攻擊：
  Phase 1：SubBytes(pt[b] XOR key_guess)              → 回復 key[0:15]
  Phase 2：SubBytes(state_before_RK1[b] XOR key_guess) → 回復 key[16:31]
  最終輸出：完整 32-byte AES-256 key
"""

import numpy as np
import matplotlib.pyplot as plt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attack_base import BaseAttack, AttackInput, AttackResult, registry
from aes256_utils import AES_Sbox, hw_table, compute_state_before_rk1

hw_vec = np.vectorize(lambda x: bin(x).count('1'))
K256   = np.arange(256)


def _cpa_correlate(intermediates: np.ndarray, traces: np.ndarray) -> np.ndarray:
    """
    對 16 個 bytes 分別計算 Pearson 相關係數。

    intermediates : (N, 16, 256)  每條 trace × 每個 byte × 256 個 key 猜測的中間值 HW
    traces        : (N, L)        功耗波形

    回傳 r : (16, 256, L)
    """
    N, L = traces.shape
    t = traces.astype(np.float64)
    t_sum  = t.sum(axis=0)               # (L,)
    t2_sum = (t ** 2).sum(axis=0)        # (L,)

    r = np.zeros((16, 256, L))
    for b in range(16):
        hw = intermediates[:, b, :].astype(np.float64)  # (N, 256)
        h_sum  = hw.sum(axis=0)           # (256,)
        h2_sum = (hw ** 2).sum(axis=0)    # (256,)
        ht_sum = hw.T @ t                 # (256, L)

        num   = N * ht_sum - np.outer(h_sum, t_sum)
        dh    = np.sqrt(N * h2_sum - h_sum ** 2)
        dt    = np.sqrt(N * t2_sum - t_sum ** 2)
        denom = np.outer(dh, dt)
        with np.errstate(divide='ignore', invalid='ignore'):
            r[b] = np.where(denom != 0, num / denom, 0)
    return r


class CPAAttack(BaseAttack):
    name         = "cpa256"
    display_name = "Correlation Power Analysis (CPA) — AES-256"
    description  = (
        "兩階段 CPA：Phase 1 用第一輪 SubBytes 回復 key[0:15]，"
        "Phase 2 用第二輪 SubBytes 輸出回復 key[16:31]，"
        "最終輸出完整 32-byte AES-256 key。"
    )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)

        traces = (data.preprocessed_traces if data.preprocessed_traces is not None
                  else data.traces).astype(np.float64)
        pt = data.plaintexts[:, :16].astype(np.uint8)
        N, L = traces.shape

        # ── Phase 1：回復 key[0:15] ──────────────────────────────
        # 中間值 HW：SubBytes(pt[b] XOR key_guess)
        inter1 = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            sbox_out      = AES_Sbox[np.bitwise_xor(pt[:, b:b+1], K256[np.newaxis, :])]
            inter1[:, b, :] = hw_table[sbox_out]

        r1 = _cpa_correlate(inter1, traces)
        key1 = np.array([int(np.argmax(np.max(np.abs(r1[b]), axis=1))) for b in range(16)],
                        dtype=np.uint8)

        # ── Phase 2：回復 key[16:31] ─────────────────────────────
        # 中間值 HW：SubBytes(state_before_RK1[b] XOR key_guess)
        state = compute_state_before_rk1(pt, key1)   # (N, 16)
        inter2 = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            inter2[:, b, :] = hw_table[AES_Sbox[
                np.bitwise_xor(state[:, b:b+1], K256[np.newaxis, :])
            ]]

        r2 = _cpa_correlate(inter2, traces)
        key2 = np.array([int(np.argmax(np.max(np.abs(r2[b]), axis=1))) for b in range(16)],
                        dtype=np.uint8)

        full_key = key1.tolist() + key2.tolist()

        # ── 畫圖 ─────────────────────────────────────────────────
        fig, axes = plt.subplots(4, 8, figsize=(32, 16))
        for b in range(16):
            axes[b // 4, b % 4].set_title(f"P1 Byte{b}", fontsize=8)
            axes[b // 4, b % 4].set_ylim(-1, 1)
            axes[b // 4, b % 4].plot(r1[b].T, alpha=0.2, linewidth=0.4)
            axes[b // 4, (b % 4) + 4].set_title(f"P2 Byte{b+16}", fontsize=8)
            axes[b // 4, (b % 4) + 4].set_ylim(-1, 1)
            axes[b // 4, (b % 4) + 4].plot(r2[b].T, alpha=0.2, linewidth=0.4)
        plt.suptitle("CPA — AES-256  Left=Phase1(key[0:15])  Right=Phase2(key[16:31])", fontsize=12)
        plt.tight_layout()

        return AttackResult(
            algorithm    = self.name,
            key_hex      = bytes(full_key).hex(),
            key_bytes    = full_key,
            num_traces   = N,
            trace_length = L,
            plot_base64  = self.plot_to_base64(fig),
            extra        = {
                "phase1_key": bytes(key1).hex(),
                "phase2_key": bytes(key2).hex(),
            },
        )


registry.register(CPAAttack())
