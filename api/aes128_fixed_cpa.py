"""Vectorized AES-128 CPA for the two whitelisted ChipWhisperer fixed captures.

This leaves the existing upload/algorithm implementations unchanged.  The
recorded key is used only after ranking candidates, for UI verification.
"""

from __future__ import annotations

import numpy as np
import matplotlib.pyplot as plt

from attack_base import AttackInput, AttackResult, BaseAttack
from attacks.cpa import AES_Sbox


_KEYS = np.arange(256, dtype=np.uint8)
_HW8 = np.unpackbits(np.arange(256, dtype=np.uint8)[:, None], axis=1).sum(axis=1).astype(np.float32)


def run_fixed_aes128_cpa(data: AttackInput) -> AttackResult:
    """Rank all 256 SBox-output HW hypotheses for every AES-128 key byte."""
    if data.traces.ndim != 2 or data.plaintexts.shape != (data.traces.shape[0], 16):
        raise ValueError("AES-128 traces / plaintexts shape 不符")

    n_traces, n_samples = data.traces.shape
    if n_traces < 3:
        raise ValueError("CPA 至少需要 3 條 Trace")

    # A single centered trace matrix can be reused for all 16 key bytes.
    t = np.asarray(data.traces, dtype=np.float32)
    t = t - t.mean(axis=0, keepdims=True)
    t_norm = np.sqrt(np.sum(t * t, axis=0, dtype=np.float64)).astype(np.float32)
    t_norm[t_norm == 0] = np.inf
    t /= t_norm

    plaintexts = np.asarray(data.plaintexts, dtype=np.uint8)
    guesses = []
    scores = []
    peaks = []
    winning_curves = []
    plots_by_byte = []
    helper = BaseAttack.plot_to_base64

    for byte in range(16):
        predicted = _HW8[AES_Sbox[np.bitwise_xor(plaintexts[:, byte, None], _KEYS[None, :])]].T
        predicted -= predicted.mean(axis=1, keepdims=True)
        predicted_norm = np.sqrt(np.sum(predicted * predicted, axis=1, dtype=np.float64)).astype(np.float32)
        predicted_norm[predicted_norm == 0] = np.inf
        predicted /= predicted_norm[:, None]

        correlation = predicted @ t
        max_per_key = np.max(np.abs(correlation), axis=1)
        winner = int(np.argmax(max_per_key))
        curve = correlation[winner].copy()
        peak = int(np.argmax(np.abs(curve)))
        guesses.append(winner)
        scores.append(float(max_per_key[winner]))
        peaks.append(peak)
        winning_curves.append(curve)

        fig, ax = plt.subplots(figsize=(8.5, 3))
        ax.plot(curve, color="#007e83", linewidth=1)
        ax.axvline(peak, color="#b95b28", linestyle="--", linewidth=1)
        ax.set(title=f"AES-128 byte {byte}: 0x{winner:02x}, |r|={scores[-1]:.3f}",
               xlabel="Sample", ylabel="Pearson r", ylim=(-1, 1))
        ax.grid(alpha=0.25)
        fig.tight_layout()
        plots_by_byte.append({"byte_index": byte, "plot_base64": helper(fig)})

    fig, axes = plt.subplots(4, 4, figsize=(16, 11), constrained_layout=True)
    for byte, ax in enumerate(axes.flat):
        ax.plot(winning_curves[byte], color="#007e83", linewidth=0.8)
        ax.axvline(peaks[byte], color="#b95b28", linestyle="--", linewidth=0.8)
        ax.set(title=f"B{byte:02d} = {guesses[byte]:02X}  |r|={scores[byte]:.3f}",
               ylim=(-1, 1))
        ax.grid(alpha=0.2)

    return AttackResult(
        algorithm="cpa", key_hex=bytes(guesses).hex(), key_bytes=guesses,
        num_traces=n_traces, trace_length=n_samples,
        plot_base64=helper(fig),
        extra={"plots_by_byte": plots_by_byte, "peak_samples": peaks,
               "max_correlations": scores},
    )
