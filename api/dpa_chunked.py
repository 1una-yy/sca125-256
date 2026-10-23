"""Memory-bounded helpers for AES DPA attacks.

Every original trace sample participates in key scoring. Only the score curves
retained for plotting are downsampled, avoiding multi-GiB score cubes.
"""

from __future__ import annotations

import numpy as np


DEFAULT_CHUNK_SIZE = 512
DEFAULT_PLOT_POINTS = 512


def _validate_inputs(
    intermediates_lsb: np.ndarray, traces: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    lsb = np.asarray(intermediates_lsb, dtype=np.uint8)
    trace_array = np.asarray(traces)
    if lsb.ndim != 3 or lsb.shape[1:] != (16, 256):
        raise ValueError(
            "intermediates_lsb must have shape (N, 16, 256), "
            f"got {lsb.shape}"
        )
    if trace_array.ndim != 2 or trace_array.shape[0] != lsb.shape[0]:
        raise ValueError(
            "traces must have shape (N, L) with the same N as intermediates_lsb, "
            f"got {trace_array.shape} and {lsb.shape}"
        )
    if trace_array.shape[0] < 2 or trace_array.shape[1] < 1:
        raise ValueError("DPA requires at least 2 traces and 1 sample")
    return lsb, trace_array


def _plot_indices(trace_length: int, max_plot_points: int) -> np.ndarray:
    point_count = min(trace_length, max(1, int(max_plot_points)))
    if point_count == trace_length:
        return np.arange(trace_length, dtype=np.int64)
    return np.linspace(0, trace_length - 1, point_count, dtype=np.int64)


def difference_of_means(
    intermediates_lsb: np.ndarray,
    traces: np.ndarray,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_plot_points: int = DEFAULT_PLOT_POINTS,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Run binary Difference-of-Means DPA in bounded sample chunks."""
    lsb, trace_array = _validate_inputs(intermediates_lsb, traces)
    _, trace_length = trace_array.shape
    chunk_size = max(1, int(chunk_size))
    plot_indices = _plot_indices(trace_length, max_plot_points)
    plot_scores = np.zeros((16, 256, plot_indices.size), dtype=np.float32)
    peak_scores = np.zeros((16, 256), dtype=np.float32)

    for byte_index in range(16):
        hypotheses = lsb[:, byte_index, :].astype(np.float32)
        count_1 = hypotheses.sum(axis=0, dtype=np.float32)
        count_0 = np.float32(hypotheses.shape[0]) - count_1
        valid = (count_0 >= 2) & (count_1 >= 2)

        for start in range(0, trace_length, chunk_size):
            stop = min(start + chunk_size, trace_length)
            trace_chunk = np.ascontiguousarray(
                trace_array[:, start:stop], dtype=np.float32
            )
            total = trace_chunk.sum(axis=0, dtype=np.float32)
            sum_1 = hypotheses.T @ trace_chunk
            sum_0 = total[np.newaxis, :] - sum_1
            scores = np.zeros_like(sum_1, dtype=np.float32)
            scores[valid] = (
                sum_1[valid] / count_1[valid, np.newaxis]
                - sum_0[valid] / count_0[valid, np.newaxis]
            )
            peak_scores[byte_index] = np.maximum(
                peak_scores[byte_index], np.max(np.abs(scores), axis=1)
            )
            left = np.searchsorted(plot_indices, start, side="left")
            right = np.searchsorted(plot_indices, stop, side="left")
            if right > left:
                local_indices = plot_indices[left:right] - start
                plot_scores[byte_index, :, left:right] = scores[:, local_indices]

    guessed_key = np.argmax(peak_scores, axis=1).astype(np.uint8)
    return plot_scores, guessed_key, plot_indices


def pearson_binary(
    intermediates_lsb: np.ndarray,
    traces: np.ndarray,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_plot_points: int = DEFAULT_PLOT_POINTS,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Run binary Pearson-correlation DPA in bounded sample chunks."""
    lsb, trace_array = _validate_inputs(intermediates_lsb, traces)
    _, trace_length = trace_array.shape
    chunk_size = max(1, int(chunk_size))
    plot_indices = _plot_indices(trace_length, max_plot_points)
    plot_scores = np.zeros((16, 256, plot_indices.size), dtype=np.float32)
    peak_scores = np.zeros((16, 256), dtype=np.float32)

    for byte_index in range(16):
        hypotheses = lsb[:, byte_index, :].astype(np.float32)
        hypotheses -= hypotheses.mean(axis=0, keepdims=True, dtype=np.float32)
        hypothesis_norm = np.sqrt(
            np.sum(hypotheses * hypotheses, axis=0, dtype=np.float32)
        )
        valid = hypothesis_norm > 0

        for start in range(0, trace_length, chunk_size):
            stop = min(start + chunk_size, trace_length)
            trace_chunk = np.array(
                trace_array[:, start:stop], dtype=np.float32, order="C", copy=True
            )
            trace_chunk -= trace_chunk.mean(axis=0, keepdims=True, dtype=np.float32)
            trace_norm = np.sqrt(
                np.sum(trace_chunk * trace_chunk, axis=0, dtype=np.float32)
            )
            numerator = hypotheses.T @ trace_chunk
            denominator = hypothesis_norm[:, np.newaxis] * trace_norm[np.newaxis, :]
            scores = np.zeros_like(numerator, dtype=np.float32)
            np.divide(
                numerator,
                denominator,
                out=scores,
                where=valid[:, np.newaxis] & (denominator > 0),
            )
            peak_scores[byte_index] = np.maximum(
                peak_scores[byte_index], np.max(np.abs(scores), axis=1)
            )
            left = np.searchsorted(plot_indices, start, side="left")
            right = np.searchsorted(plot_indices, stop, side="left")
            if right > left:
                local_indices = plot_indices[left:right] - start
                plot_scores[byte_index, :, left:right] = scores[:, local_indices]

    guessed_key = np.argmax(peak_scores, axis=1).astype(np.uint8)
    return plot_scores, guessed_key, plot_indices
