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


def _cpa_correlate(source_bytes: np.ndarray, traces: np.ndarray):
    """Memory-bounded CPA; all samples are scored, only 512 points are retained for plots."""
    _, trace_length = traces.shape
    # Four bytes per GEMM gives BLAS a larger, more efficient matrix while
    # keeping peak temporary memory bounded for the 20k-trace datasets.
    byte_block_size = 4
    chunk_size = 768
    plot_samples = np.linspace(0, trace_length - 1, min(512, trace_length), dtype=np.int64)
    plot_scores = np.zeros((16, 256, plot_samples.size), dtype=np.float32)
    peak_scores = np.zeros((16, 256), dtype=np.float32)

    for byte_start in range(0, 16, byte_block_size):
        byte_stop = min(byte_start + byte_block_size, 16)
        hypotheses = np.concatenate([
            hw_table[AES_Sbox[np.bitwise_xor(
                source_bytes[:, byte_index:byte_index + 1], K256[np.newaxis, :]
            )]]
            for byte_index in range(byte_start, byte_stop)
        ], axis=1).astype(np.float32)
        hypotheses -= hypotheses.mean(axis=0, keepdims=True, dtype=np.float32)
        hypothesis_norm = np.sqrt(
            np.sum(hypotheses * hypotheses, axis=0, dtype=np.float32)
        )

        for start in range(0, trace_length, chunk_size):
            stop = min(start + chunk_size, trace_length)
            trace_chunk = np.array(traces[:, start:stop], dtype=np.float32, order="C", copy=True)
            trace_chunk -= trace_chunk.mean(axis=0, keepdims=True, dtype=np.float32)
            trace_norm = np.sqrt(np.sum(trace_chunk * trace_chunk, axis=0, dtype=np.float32))
            numerator = hypotheses.T @ trace_chunk
            denominator = hypothesis_norm[:, np.newaxis] * trace_norm[np.newaxis, :]
            scores = np.zeros_like(numerator, dtype=np.float32)
            np.divide(numerator, denominator, out=scores, where=denominator > 0)
            block_scores = scores.reshape(byte_stop - byte_start, 256, stop - start)
            peak_scores[byte_start:byte_stop] = np.maximum(
                peak_scores[byte_start:byte_stop],
                np.max(np.abs(block_scores), axis=2),
            )
            left = np.searchsorted(plot_samples, start, side="left")
            right = np.searchsorted(plot_samples, stop, side="left")
            if right > left:
                local = plot_samples[left:right] - start
                plot_scores[byte_start:byte_stop, :, left:right] = block_scores[:, :, local]

    return plot_scores, np.argmax(peak_scores, axis=1).astype(np.uint8), plot_samples


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
                  else data.traces)
        pt = data.plaintexts[:, :16].astype(np.uint8)
        N, L = traces.shape

        # ── Phase 1：回復 key[0:15] ──────────────────────────────
        # 中間值 HW：SubBytes(pt[b] XOR key_guess)
        r1, key1, plot_samples1 = _cpa_correlate(pt, traces)

        # ── Phase 2：回復 key[16:31] ─────────────────────────────
        # 中間值 HW：SubBytes(state_before_RK1[b] XOR key_guess)
        state = compute_state_before_rk1(pt, key1)   # (N, 16)
        r2, key2, plot_samples2 = _cpa_correlate(state, traces)

        full_key = key1.tolist() + key2.tolist()

        # ── 畫圖 ─────────────────────────────────────────────────
        fig, axes = plt.subplots(4, 8, figsize=(32, 16))
        for b in range(16):
            axes[b // 4, b % 4].set_title(f"P1 Byte{b}", fontsize=8)
            axes[b // 4, b % 4].set_ylim(-1, 1)
            axes[b // 4, b % 4].plot(plot_samples1, r1[b].T, alpha=0.2, linewidth=0.4)
            axes[b // 4, (b % 4) + 4].set_title(f"P2 Byte{b+16}", fontsize=8)
            axes[b // 4, (b % 4) + 4].set_ylim(-1, 1)
            axes[b // 4, (b % 4) + 4].plot(plot_samples2, r2[b].T, alpha=0.2, linewidth=0.4)
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
                "plots_by_byte": (
                    self.generate_byte_plots(r1, offset=0, sample_indices=plot_samples1)
                    + self.generate_byte_plots(r2, offset=16, sample_indices=plot_samples2)
                ),
                "plot_sample_indices": plot_samples1.tolist(),
            },
        )


registry.register(CPAAttack())
