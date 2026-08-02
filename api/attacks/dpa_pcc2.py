"""
attacks/dpa_pcc.py
DPA — Pearson Correlation Coefficient（LSB 分組）攻擊模組 — AES-256 完整版。

兩階段攻擊：
  Phase 1：PCC on LSB of SubBytes(pt[b] XOR key_guess)           → 回復 key[0:15]
  Phase 2：PCC on LSB of SubBytes(state_before_RK1[b] XOR key_guess) → 回復 key[16:31]
  最終輸出：完整 32-byte AES-256 key
"""

import numpy as np
import matplotlib.pyplot as plt
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from attack_base import BaseAttack, AttackInput, AttackResult, registry
from aes256_utils import AES_Sbox, compute_state_before_rk1

K256 = np.arange(256)


def _pcc_attack(get_lsb_fn, traces: np.ndarray) -> tuple:
    """
    Pearson Correlation Coefficient DPA 攻擊（incremental）。

    get_lsb_fn : callable(i) → (16, 256) uint8，第 i 條 trace 的 LSB 中間值
    traces     : (N, L) float64

    回傳 (r, guess_key)
    """
    N, L = traces.shape
    r         = np.zeros((16, 256, L))
    h_sum     = np.zeros((16, 256))
    h2_sum    = np.zeros((16, 256))
    t_sum     = np.zeros(L)
    t2_sum    = np.zeros(L)
    ht_sum    = np.zeros((16, 256, L))
    guess_key = np.zeros(16, dtype=int)

    for i in range(N):
        n       = i + 1
        ti      = traces[i]
        t_sum  += ti
        t2_sum += ti ** 2
        std_t   = np.sqrt(t2_sum - t_sum ** 2 / n) + 1e-40

        lsb = get_lsb_fn(i)                          # (16, 256) float

        for b in range(16):
            h            = lsb[b].astype(np.float64)  # (256,)
            h_sum[b]    += h
            h2_sum[b]   += h ** 2
            ht_sum[b]   += np.outer(h, ti)

            std_h    = np.sqrt(h2_sum[b] - h_sum[b] ** 2 / n) + 1e-40
            r[b]     = (ht_sum[b] - np.outer(h_sum[b], t_sum) / n) / np.outer(std_h, std_t)

    for b in range(16):
        valid = (h2_sum[b] - h_sum[b] ** 2 / N) > 1e-12
        r[b, ~valid] = 0.0
        guess_key[b] = int(np.argmax(np.max(np.abs(r[b]), axis=1)))

    return r, guess_key


class DPAPCCAttack(BaseAttack):
    name         = "dpa_pcc256"
    display_name = "DPA — Pearson Correlation (LSB) — AES-256"
    description  = (
        "兩階段 DPA PCC：Phase 1 用第一輪 SBox LSB 回復 key[0:15]，"
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
        # 預先計算所有 trace 的 LSB 中間值
        lsb1 = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            lsb1[:, b, :] = AES_Sbox[
                np.bitwise_xor(pt[:, b:b+1], K256[np.newaxis, :])
            ] & 0x01

        r1, key1 = _pcc_attack(lambda i: lsb1[i], traces)

        # ── Phase 2：回復 key[16:31] ─────────────────────────────
        state  = compute_state_before_rk1(pt, key1.astype(np.uint8))
        lsb2   = np.zeros((N, 16, 256), dtype=np.uint8)
        for b in range(16):
            lsb2[:, b, :] = AES_Sbox[
                np.bitwise_xor(state[:, b:b+1], K256[np.newaxis, :])
            ] & 0x01

        r2, key2 = _pcc_attack(lambda i: lsb2[i], traces)

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
        plt.suptitle("DPA PCC — AES-256  Left=Phase1(key[0:15])  Right=Phase2(key[16:31])", fontsize=12)
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


registry.register(DPAPCCAttack())
