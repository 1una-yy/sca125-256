"""
attacks/dpa_dom.py
DPA — Difference of Means（LSB 分組）攻擊模組 — AES-256 完整版。

兩階段攻擊：
  Phase 1：LSB of SubBytes(pt[b] XOR key_guess)           → 回復 key[0:15]
  Phase 2：LSB of SubBytes(state_before_RK1[b] XOR key_guess) → 回復 key[16:31]
  最終輸出：完整 32-byte AES-256 key
"""

import numpy as np
import matplotlib.pyplot as plt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_base import BaseAttack, AttackInput, AttackResult, registry
from aes256_utils import AES_Sbox, compute_state_before_rk1

K256 = np.arange(256)


def _dom_attack(intermediates_lsb: np.ndarray, traces: np.ndarray) -> tuple:
    """
    Difference of Means 攻擊。

    intermediates_lsb : (N, 16, 256) uint8，值只有 0 或 1（LSB）
    traces            : (N, L) float64

    回傳 (r, guess_key)
      r         : (16, 256, L)
      guess_key : (16,) int
    """
    N, L = traces.shape
    r         = np.zeros((16, 256, L))
    guess_key = np.zeros(16, dtype=int)

    for b in range(16):
        lsb    = intermediates_lsb[:, b, :]        # (N, 256)
        sum_0  = np.zeros((256, L))
        sum_1  = np.zeros((256, L))
        n_0    = np.zeros(256)
        n_1    = np.zeros(256)

        for i in range(N):
            mask1        = lsb[i] == 1              # (256,) bool
            sum_1[mask1] += traces[i]
            sum_0[~mask1]+= traces[i]
            n_1[mask1]   += 1
            n_0[~mask1]  += 1

        valid = (n_0 >= 2) & (n_1 >= 2)
        r[b, valid] = (sum_1[valid] / n_1[valid, None]
                       - sum_0[valid] / n_0[valid, None])
        guess_key[b] = int(np.argmax(np.max(np.abs(r[b]), axis=1)))

    return r, guess_key


class DPADoMAttack(BaseAttack):
    name         = "dpa_dom256"
    display_name = "DPA — Difference of Means (LSB) — AES-256"
    description  = (
        "兩階段 DPA DoM：Phase 1 用第一輪 SBox LSB 回復 key[0:15]，"
        "Phase 2 用第二輪 SBox 輸出的 LSB 回復 key[16:31]，"
        "最終輸出完整 32-byte AES-256 key。"
    )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)
        traces = (data.preprocessed_traces if data.preprocessed_traces is not None
                  else data.traces).astype(np.float64)
        pt = data.plaintexts[:, :16].astype(np.uint8)
        N, L = traces.shape

        # ── Phase 1：回復 key[0:15] ──────────────────────────────
        # LSB of SubBytes(pt[b] XOR key_guess)
        inter1_lsb = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            sbox_out         = AES_Sbox[np.bitwise_xor(pt[:, b:b+1], K256[np.newaxis, :])]
            inter1_lsb[:, b, :] = sbox_out & 0x01

        r1, key1 = _dom_attack(inter1_lsb, traces)

        # ── Phase 2：回復 key[16:31] ─────────────────────────────
        # LSB of SubBytes(state_before_RK1[b] XOR key_guess)
        state = compute_state_before_rk1(pt, key1.astype(np.uint8))
        inter2_lsb = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            inter2_lsb[:, b, :] = AES_Sbox[
                np.bitwise_xor(state[:, b:b+1], K256[np.newaxis, :])
            ] & 0x01

        r2, key2 = _dom_attack(inter2_lsb, traces)

        full_key = key1.tolist() + key2.tolist()

        # ── 畫圖 ─────────────────────────────────────────────────
        fig, axes = plt.subplots(4, 8, figsize=(32, 16))
        for b in range(16):
            axes[b // 4, b % 4].set_title(f"P1 Byte{b}", fontsize=8)
            axes[b // 4, b % 4].plot(r1[b].T, alpha=0.2, linewidth=0.4)
            axes[b // 4, (b % 4) + 4].set_title(f"P2 Byte{b+16}", fontsize=8)
            axes[b // 4, (b % 4) + 4].plot(r2[b].T, alpha=0.2, linewidth=0.4)
        plt.suptitle("DPA DoM — AES-256  Left=Phase1(key[0:15])  Right=Phase2(key[16:31])", fontsize=12)
        plt.tight_layout()

        return AttackResult(
            algorithm    = self.name,
            key_hex      = bytes(full_key).hex(),
            key_bytes    = full_key,
            num_traces   = N,
            trace_length = L,
            plot_base64  = self.plot_to_base64(fig),
            extra        = {
                "phase1_key": bytes(key1.astype(np.uint8)).hex(),
                "phase2_key": bytes(key2.astype(np.uint8)).hex(),
            },
        )


registry.register(DPADoMAttack())
