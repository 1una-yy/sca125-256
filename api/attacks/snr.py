"""
attacks/snr.py
SNR（訊噪比）洩漏點分析模組。

用途：計算每個採樣點在 Hamming Weight 分群下的訊噪比，用來定位功耗波形中
資訊量最大的洩漏點（POI，Point of Interest）。

注意：這不是金鑰恢復攻擊，而是輔助定位／前處理用的診斷工具，因此不回傳
金鑰猜測（key_hex / key_bytes 為空）。必須提供已知 AES-128 金鑰，才能用
SBox(明文 xor 金鑰) 的 Hamming Weight 正確分群。分析結果放在 extra 欄位：
  - leak_points   : 每個 byte SNR 最大值所在的採樣點索引
  - max_snr       : 每個 byte 的最大 SNR 值
  - used_known_key: 固定為 True

自動登錄到 registry，API 啟動時即可使用。
"""

import numpy as np
import matplotlib.pyplot as plt
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from attack_base import BaseAttack, AttackInput, AttackResult, registry

# AES S-Box
AES_Sbox = np.array([
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
])

hw_vec = np.vectorize(lambda x: bin(int(x)).count('1'))


class SNRAnalysis(BaseAttack):
    name         = "snr"
    display_name = "Signal-to-Noise Ratio (SNR) 洩漏點分析"
    description  = (
        "計算每個採樣點的訊噪比，定位功耗波形中資訊量最大的洩漏點；"
        "屬於診斷/前處理工具，需要已知金鑰，不是金鑰恢復攻擊。"
    )

    def run(self, data: AttackInput) -> AttackResult:
        self.validate(data)

        traces = data.preprocessed_traces if data.preprocessed_traces is not None else data.traces
        t = traces.astype(np.float64)
        p = data.plaintexts.astype(np.uint8)
        num_traces, trace_length = t.shape

        # 正確的 AES SNR 必須以已知 key 建立 SBox 中間值 HW 標籤。
        key_source = data.known_key if data.known_key is not None else data.template_keys
        if key_source is None or len(key_source) == 0:
            raise ValueError("SNR AES-128 需要 known_key_hex（32 個十六進位字元）")
        k = np.asarray(key_source, dtype=np.uint8)
        if k.ndim == 1:
            if k.size < 16:
                raise ValueError(f"SNR AES-128 key 至少需要 16 bytes，目前為 {k.size}")
            k = np.tile(k[:16], (num_traces, 1))
        elif k.ndim == 2:
            if k.shape[1] < 16:
                raise ValueError(f"SNR AES-128 keys 必須至少 16 bytes，目前為 {k.shape}")
            if k.shape[0] == 1:
                k = np.tile(k[0, :16], (num_traces, 1))
            elif k.shape[0] == num_traces:
                k = k[:, :16]
            else:
                raise ValueError(f"SNR AES-128 keys 筆數必須是 1 或 {num_traces}，目前為 {k.shape[0]}")
        else:
            raise ValueError(f"SNR AES-128 key shape 不正確：{k.shape}")
        h = hw_vec(AES_Sbox[np.bitwise_xor(p, k)]).astype(int)
        used_known_key = True
        var = np.zeros((16, trace_length))
        avg = np.zeros((16, trace_length))
        avg_diff_hw = np.zeros((16, 9, trace_length))
        count = np.zeros((16, 9), dtype=int)

        for b in range(16):
            t_sum  = np.zeros((9, trace_length))
            t2_sum = np.zeros((9, trace_length))
            for j in range(num_traces):
                grp = h[j, b]
                t_sum[grp]  += t[j]
                t2_sum[grp] += t[j] ** 2
                count[b, grp] += 1

            prob = count[b] / num_traces                 # (9,)
            cnt_safe = np.maximum(count[b], 1)[:, None]   # 避免除以 0
            with np.errstate(divide='ignore', invalid='ignore'):
                avg_t = np.where(count[b][:, None] > 0, t_sum / cnt_safe, 0.0)
                var_t = np.where(count[b][:, None] > 0, t2_sum / cnt_safe - avg_t ** 2, 0.0)

            var[b] = np.sum((avg_t ** 2) * prob[:, None], axis=0) - np.sum(avg_t * prob[:, None], axis=0) ** 2
            avg[b] = np.sum(var_t * prob[:, None], axis=0)
            avg_diff_hw[b] = avg_t

        with np.errstate(divide='ignore', invalid='ignore'):
            snr = np.where(avg != 0, var / avg, 0.0)
        snr = np.nan_to_num(snr, nan=0.0, posinf=0.0, neginf=0.0)

        leak_points = [int(np.argmax(snr[b])) for b in range(16)]
        max_snr     = [float(np.max(snr[b])) for b in range(16)]

        fig, axes = plt.subplots(4, 4, figsize=(20, 20))
        for b in range(16):
            ax = axes[b // 4, b % 4]
            idx = leak_points[b]
            ax.plot(snr[b])
            ax.text(idx, snr[b, idx], f"[{idx}, {snr[b, idx]:.2f}]")
            ax.set_title(f"Byte {b}")
            ax.set_xlabel("Samples")
            ax.set_ylabel("SNR")
        plt.tight_layout()

        return AttackResult(
            algorithm    = self.name,
            key_hex      = "",
            key_bytes    = [],
            num_traces   = num_traces,
            trace_length = trace_length,
            plot_base64  = self.plot_to_base64(fig),
            extra = {
                "leak_points": leak_points,
                "max_snr": max_snr,
                "used_known_key": used_known_key,
                "note": "SNR 為洩漏點定位工具，非金鑰恢復攻擊，不回傳金鑰猜測。",
            },
        )


# 登錄到全域 registry
registry.register(SNRAnalysis())
