"""
attack_base.py
所有攻擊模組的共同介面（Base Class）。
新增演算法時只需繼承 BaseAttack 並實作 run()，API 會自動支援。
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
import numpy as np
import io
import base64
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ─────────────────────────────────────────────
# 標準輸入 / 輸出格式（前端只需認識這兩個）
# ─────────────────────────────────────────────

@dataclass
class AttackInput:
    """所有攻擊的統一輸入格式"""
    traces: np.ndarray            # shape: (num_traces, trace_length)
    plaintexts: np.ndarray        # shape: (num_traces, 16), dtype: uint8
    preprocessed_traces: Optional[np.ndarray] = None  # AI 定位後的 traces（可選）

    # 管理者／相容 API 可選：臨時 profiling 資料；一般使用者採伺服器預建模板
    template_traces: Optional[np.ndarray] = None      # shape: (N_template, trace_length)
    template_plaintexts: Optional[np.ndarray] = None  # shape: (N_template, 16)
    template_keys: Optional[np.ndarray] = None        # shape: (N_template, 16 or 32)
    known_key: Optional[np.ndarray] = None            # shape: (16,) or (32,)，供 SNR/結果校準


@dataclass
class AttackResult:
    """所有攻擊的統一輸出格式"""
    algorithm: str                # 演算法名稱，e.g. "cpa"
    key_hex: str                  # 猜測金鑰，e.g. "2b7e151628aed2a6..."
    key_bytes: list               # [43, 126, 21, ...]
    num_traces: int               # 使用的 trace 數量
    trace_length: int             # 每條 trace 的採樣點數
    plot_base64: str              # 相關係數圖（base64 PNG）
    extra: dict = field(default_factory=dict)  # 各演算法額外資訊（可選）


# ─────────────────────────────────────────────
# 演算法基底類別
# ─────────────────────────────────────────────

class BaseAttack(ABC):
    """
    所有攻擊模組必須繼承此類別。

    範例：
        class MyCPA(BaseAttack):
            name        = "cpa"
            display_name = "Correlation Power Analysis"
            description  = "使用 Pearson 相關係數進行旁通道攻擊"

            def run(self, data: AttackInput) -> AttackResult:
                ...
    """

    # 子類別必須填寫以下三個屬性
    name: str = ""              # 英文 ID，作為 API 路徑，e.g. "cpa"
    display_name: str = ""      # 顯示名稱
    description: str = ""       # 說明

    @abstractmethod
    def run(self, data: AttackInput) -> AttackResult:
        """執行攻擊，輸入 AttackInput，輸出 AttackResult"""
        ...

    def validate(self, data: AttackInput):
        """驗證輸入格式，若有問題直接 raise ValueError"""
        t, p = data.traces, data.plaintexts
        if t.ndim != 2:
            raise ValueError(f"traces 應為 2D array，目前為 {t.ndim}D")
        if p.ndim != 2 or p.shape[1] != 16:
            raise ValueError(f"plaintexts 應為 (N, 16)，目前為 {p.shape}")
        # ChipWhisperer 錄製時首條 trace 偶爾為空，自動去掉
        if t.shape[0] == p.shape[0] + 1:
            data.traces = t[1:]
            if data.preprocessed_traces is not None and data.preprocessed_traces.shape[0] == p.shape[0] + 1:
                data.preprocessed_traces = data.preprocessed_traces[1:]
        elif t.shape[0] != p.shape[0]:
            raise ValueError(f"traces ({t.shape[0]}) 與 plaintexts ({p.shape[0]}) 筆數不符")

    @staticmethod
    def plot_to_base64(fig) -> str:
        """把 matplotlib figure 轉成 base64 PNG 字串"""
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=100, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode("utf-8")


# ─────────────────────────────────────────────
# 演算法登錄機制（Registry）
# ─────────────────────────────────────────────

class AttackRegistry:
    """
    管理所有已登錄的攻擊演算法。
    新增演算法只需在對應 .py 檔案呼叫 registry.register(MyAttack())。
    """

    def __init__(self):
        self._attacks: dict[str, BaseAttack] = {}

    def register(self, attack: BaseAttack):
        """登錄一個攻擊演算法"""
        self._attacks[attack.name] = attack
        print(f"[Registry] 已登錄演算法：{attack.name} ({attack.display_name})")

    def get(self, name: str) -> Optional[BaseAttack]:
        return self._attacks.get(name)

    def list_all(self) -> list[dict]:
        """回傳所有已登錄演算法的資訊（給前端顯示選單用）"""
        return [
            {
                "id": a.name,
                "display_name": a.display_name,
                "description": a.description,
            }
            for a in self._attacks.values()
        ]


# 全域 registry 實例（整個 API 共用同一個）
registry = AttackRegistry()
