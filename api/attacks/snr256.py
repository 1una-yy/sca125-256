"""
AES-256 SNR 洩漏點分析。

依照 SNR_AES256_3.ipynb 的兩階段模型：
  Phase 1: HW(SBox(plaintext XOR key[0:16]))
  Phase 2: HW(SBox(state_before_RK1 XOR key[16:32]))

SNR 是洩漏診斷工具，不回復金鑰。為了正確建立 32-byte HW 標籤，
呼叫 API 時必須提供 64 個十六進位字元的 known_key_hex。
"""

import os
import sys

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from aes256_utils import AES_Sbox, compute_state_before_rk1, hw_table
from attack_base import AttackInput, AttackResult, BaseAttack, registry


def _compute_snr(traces: np.ndarray, labels: np.ndarray) -> np.ndarray:
    """以 HW=0..8 分群，計算各 byte、各採樣點的 signal/noise。"""
    num_traces, trace_length = traces.shape
    num_bytes = labels.shape[1]
    snr = np.zeros((num_bytes, trace_length), dtype=np.float64)

    for byte_index in range(num_bytes):
        group_means = np.zeros((9, trace_length), dtype=np.float64)
        group_vars = np.zeros((9, trace_length), dtype=np.float64)
        probabilities = np.zeros(9, dtype=np.float64)

        for hw in range(9):
            mask = labels[:, byte_index] == hw
            count = int(np.count_nonzero(mask))
            if count == 0:
                continue
            group = traces[mask]
            group_means[hw] = group.mean(axis=0)
            group_vars[hw] = group.var(axis=0)
            probabilities[hw] = count / num_traces

        signal = (
            np.sum(group_means ** 2 * probabilities[:, None], axis=0)
            - np.sum(group_means * probabilities[:, None], axis=0) ** 2
        )
        noise = np.sum(group_vars * probabilities[:, None], axis=0)
        with np.errstate(divide="ignore", invalid="ignore"):
            snr[byte_index] = np.where(noise > 0, signal / noise, 0.0)

    return np.nan_to_num(snr, nan=0.0, posinf=0.0, neginf=0.0)


class SNRAnalysis256(BaseAttack):
    name = "snr256"
    display_name = "Signal-to-Noise Ratio (SNR) — AES-256"
    description = (
        "以已知 32-byte 金鑰建立兩階段 HW 標籤，計算 32 個 key bytes 的 SNR 與 POI；"
        "這是洩漏點分析，不回傳金鑰猜測。"
    )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)
        if data.known_key is None:
            raise ValueError("SNR AES-256 需要 known_key_hex（64 個十六進位字元）")

        known_key = np.asarray(data.known_key, dtype=np.uint8).reshape(-1)
        if known_key.size != 32:
            raise ValueError(
                f"SNR AES-256 的 known_key_hex 必須是 32 bytes，目前為 {known_key.size} bytes"
            )

        traces = (
            data.preprocessed_traces
            if data.preprocessed_traces is not None
            else data.traces
        ).astype(np.float64)
        plaintexts = data.plaintexts[:, :16].astype(np.uint8)
        num_traces, trace_length = traces.shape

        phase1_labels = hw_table[
            AES_Sbox[plaintexts ^ known_key[:16][np.newaxis, :]]
        ]
        state_before_rk1 = compute_state_before_rk1(plaintexts, known_key[:16])
        phase2_labels = hw_table[
            AES_Sbox[state_before_rk1 ^ known_key[16:][np.newaxis, :]]
        ]
        labels = np.concatenate((phase1_labels, phase2_labels), axis=1)
        snr = _compute_snr(traces, labels)

        leak_points = [int(np.argmax(snr[b])) for b in range(32)]
        max_snr = [float(np.max(snr[b])) for b in range(32)]

        fig, axes = plt.subplots(8, 4, figsize=(20, 28))
        for b in range(32):
            ax = axes[b // 4, b % 4]
            point = leak_points[b]
            ax.plot(snr[b], linewidth=0.8)
            ax.scatter([point], [snr[b, point]], color="crimson", s=12)
            phase = "P1" if b < 16 else "P2"
            ax.set_title(f"{phase} Byte {b} — POI {point}", fontsize=9)
            ax.set_xlabel("Samples")
            ax.set_ylabel("SNR")
        plt.suptitle("SNR — AES-256 (32 key bytes)", fontsize=14)
        plt.tight_layout()

        return AttackResult(
            algorithm=self.name,
            key_hex="",
            key_bytes=[],
            num_traces=num_traces,
            trace_length=trace_length,
            plot_base64=self.plot_to_base64(fig),
            extra={
                "aes_bits": 256,
                "leak_points": leak_points,
                "max_snr": max_snr,
                "used_known_key": True,
                "note": "SNR 為洩漏點定位工具，非金鑰恢復攻擊，不回傳金鑰猜測。",
            },
        )


registry.register(SNRAnalysis256())