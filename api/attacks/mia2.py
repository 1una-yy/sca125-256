"""
attacks/mia.py
MIA — Mutual Information Analysis 攻擊模組 — AES-256 完整版。

兩階段攻擊：
  Phase 1：MI on HW of SubBytes(pt[b] XOR key_guess)           → 回復 key[0:15]
  Phase 2：MI on HW of SubBytes(state_before_RK1[b] XOR key_guess) → 回復 key[16:31]
  最終輸出：完整 32-byte AES-256 key

注意：MIA 計算量大，SAMPLE_STEP 預設 10（每 10 個 sample 取一點）。
"""

import numpy as np
import matplotlib.pyplot as plt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_base import BaseAttack, AttackInput, AttackResult, registry
from aes256_utils import AES_Sbox, hw_table, compute_state_before_rk1

K256 = np.arange(256)


def _mi_histogram(x_vals: np.ndarray, y_vals: np.ndarray, bins: int = 9) -> float:
    """直方圖法估計互資訊 I(X; Y)"""
    N = len(x_vals)
    x_bins = np.arange(bins + 1) - 0.5
    y_bins = np.linspace(y_vals.min(), y_vals.max(), bins + 1)
    joint, _, _ = np.histogram2d(x_vals.astype(float), y_vals, bins=[x_bins, y_bins])
    joint /= N
    px = joint.sum(axis=1)
    py = joint.sum(axis=0)
    mi = 0.0
    for i in range(len(px)):
        for j in range(len(py)):
            if joint[i, j] > 0 and px[i] > 0 and py[j] > 0:
                mi += joint[i, j] * np.log2(joint[i, j] / (px[i] * py[j]))
    return mi


def _mia_attack(hw_intermediates: np.ndarray, t_sub: np.ndarray) -> tuple:
    """
    對 16 個 bytes 執行 MIA。

    hw_intermediates : (N, 16, 256) uint8 — HW 中間值
    t_sub            : (N, S)       float — 降採樣後的 traces

    回傳 (mi_max, guess_key)
    """
    N, S = t_sub.shape
    mi_max    = np.zeros((16, 256))
    guess_key = np.zeros(16, dtype=int)

    for b in range(16):
        for kg in range(256):
            hw_pred = hw_intermediates[:, b, kg].astype(float)
            mi_vals = np.array([_mi_histogram(hw_pred, t_sub[:, s]) for s in range(S)])
            mi_max[b, kg] = mi_vals.max()
        guess_key[b] = int(np.argmax(mi_max[b]))

    return mi_max, guess_key


class MIAAttack(BaseAttack):
    name         = "mia256"
    display_name = "Mutual Information Analysis (MIA) — AES-256"
    description  = (
        "兩階段 MIA：Phase 1 用第一輪 SBox HW 回復 key[0:15]，"
        "Phase 2 用第二輪 SBox 輸出的 HW 回復 key[16:31]，"
        "最終輸出完整 32-byte AES-256 key。"
    )

    SAMPLE_STEP = 10   # 每隔幾個 sample 計算一次（1 = 全部，但很慢）

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)
        traces = (data.preprocessed_traces if data.preprocessed_traces is not None
                  else data.traces).astype(np.float64)
        pt = data.plaintexts[:, :16].astype(np.uint8)
        N, L = traces.shape

        sample_pts = np.arange(0, L, self.SAMPLE_STEP)
        t_sub      = traces[:, sample_pts]             # (N, S)

        # ── Phase 1：回復 key[0:15] ──────────────────────────────
        hw1 = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            sbox_out   = AES_Sbox[np.bitwise_xor(pt[:, b:b+1], K256[np.newaxis, :])]
            hw1[:, b, :] = hw_table[sbox_out]

        mi1, key1 = _mia_attack(hw1, t_sub)

        # ── Phase 2：回復 key[16:31] ─────────────────────────────
        state = compute_state_before_rk1(pt, key1.astype(np.uint8))
        hw2   = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            hw2[:, b, :] = hw_table[AES_Sbox[
                np.bitwise_xor(state[:, b:b+1], K256[np.newaxis, :])
            ]]

        mi2, key2 = _mia_attack(hw2, t_sub)

        full_key = key1.tolist() + key2.tolist()

        # ── 畫圖 ─────────────────────────────────────────────────
        fig, axes = plt.subplots(4, 8, figsize=(32, 16))
        for b in range(16):
            ax1 = axes[b // 4, b % 4]
            ax1.bar(range(256), mi1[b], color='lightsteelblue', width=1.0)
            ax1.bar(key1[b], mi1[b, key1[b]], color='crimson', width=2)
            ax1.set_title(f"P1 B{b} Guess={key1[b]:02X}h", fontsize=8)

            ax2 = axes[b // 4, (b % 4) + 4]
            ax2.bar(range(256), mi2[b], color='lightsteelblue', width=1.0)
            ax2.bar(key2[b], mi2[b, key2[b]], color='crimson', width=2)
            ax2.set_title(f"P2 B{b+16} Guess={key2[b]:02X}h", fontsize=8)

        plt.suptitle("MIA — AES-256  Left=Phase1(key[0:15])  Right=Phase2(key[16:31])", fontsize=12)
        plt.tight_layout()

        return AttackResult(
            algorithm    = self.name,
            key_hex      = bytes(full_key).hex(),
            key_bytes    = full_key,
            num_traces   = N,
            trace_length = L,
            plot_base64  = self.plot_to_base64(fig),
            extra        = {
                "phase1_key":  bytes(key1.astype(np.uint8)).hex(),
                "phase2_key":  bytes(key2.astype(np.uint8)).hex(),
                "sample_step": self.SAMPLE_STEP,
                "mode":        "downsampled_approximation",
            },
        )


registry.register(MIAAttack())
