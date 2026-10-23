"""AES-256 two-phase Difference-of-Means DPA."""

import os
import sys

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from aes256_utils import AES_Sbox, compute_state_before_rk1
from attack_base import AttackInput, AttackResult, BaseAttack, registry
from dpa_chunked import difference_of_means


K256 = np.arange(256)


class DPADoMAttack(BaseAttack):
    name = "dpa_dom256"
    display_name = "DPA — Difference of Means (LSB) — AES-256"
    description = (
        "兩階段 DPA DoM：Phase 1 用第一輪 SBox LSB 回復 key[0:15]，"
        "Phase 2 用第二輪 SBox 輸出的 LSB 回復 key[16:31]，"
        "最終輸出完整 32-byte AES-256 key。"
    )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)
        traces = (
            data.preprocessed_traces
            if data.preprocessed_traces is not None
            else data.traces
        )
        pt = data.plaintexts[:, :16].astype(np.uint8)
        trace_count, trace_length = traces.shape

        inter1_lsb = np.zeros((trace_count, 16, 256), dtype=np.uint8)
        for byte_index in range(16):
            sbox_out = AES_Sbox[
                np.bitwise_xor(
                    pt[:, byte_index : byte_index + 1], K256[np.newaxis, :]
                )
            ]
            inter1_lsb[:, byte_index, :] = sbox_out & 0x01

        r1, key1, plot_samples = difference_of_means(inter1_lsb, traces)
        del inter1_lsb

        state = compute_state_before_rk1(pt, key1)
        inter2_lsb = np.zeros((trace_count, 16, 256), dtype=np.uint8)
        for byte_index in range(16):
            inter2_lsb[:, byte_index, :] = AES_Sbox[
                np.bitwise_xor(
                    state[:, byte_index : byte_index + 1], K256[np.newaxis, :]
                )
            ] & 0x01

        r2, key2, plot_samples2 = difference_of_means(inter2_lsb, traces)
        full_key = key1.tolist() + key2.tolist()

        fig, axes = plt.subplots(4, 8, figsize=(32, 16))
        for byte_index in range(16):
            axes[byte_index // 4, byte_index % 4].set_title(
                f"P1 Byte{byte_index}", fontsize=8
            )
            axes[byte_index // 4, byte_index % 4].plot(
                plot_samples, r1[byte_index].T, alpha=0.2, linewidth=0.4
            )
            axes[byte_index // 4, (byte_index % 4) + 4].set_title(
                f"P2 Byte{byte_index + 16}", fontsize=8
            )
            axes[byte_index // 4, (byte_index % 4) + 4].plot(
                plot_samples2, r2[byte_index].T, alpha=0.2, linewidth=0.4
            )
        plt.suptitle(
            "DPA DoM — AES-256  Left=Phase1(key[0:15])  "
            "Right=Phase2(key[16:31])",
            fontsize=12,
        )
        plt.tight_layout()

        return AttackResult(
            algorithm=self.name,
            key_hex=bytes(full_key).hex(),
            key_bytes=full_key,
            num_traces=trace_count,
            trace_length=trace_length,
            plot_base64=self.plot_to_base64(fig),
            extra={
                "phase1_key": bytes(key1).hex(),
                "phase2_key": bytes(key2).hex(),
                "plots_by_byte": (
                    self.generate_byte_plots(r1, offset=0)
                    + self.generate_byte_plots(r2, offset=16)
                ),
                "plot_sample_indices": plot_samples.tolist(),
            },
        )


registry.register(DPADoMAttack())
