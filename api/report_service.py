"""AI-assisted security report generation and PDF export for the SCA platform."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"), override=False)
except ImportError:
    pass

STANDARD_TITLE = "資通訊產品供應鏈資安標準 第一部：晶片安全 v1.1[20251114]"
STANDARD_CLAUSE = "5.1.1.3"
STANDARD_REQUIREMENT = (
    "產品在執行密碼運算的過程中之紀錄，應防止攻擊者透過差分功耗分析或"
    "差分電磁分析，找出產品所使用的關鍵安全參數（CSP）。"
)
DEFAULT_MODEL = "gemini-3-flash-preview"


def report_config() -> Dict[str, Any]:
    return {
        "ai_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "model": os.getenv("GEMINI_MODEL", DEFAULT_MODEL),
        "provider": "Google Gemini API",
        "key_source": "GEMINI_API_KEY environment variable",
    }


def _now_taipei() -> datetime:
    return datetime.now(timezone(timedelta(hours=8)))


def _document_id(payload: Dict[str, Any], now: datetime) -> str:
    digest = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:8].upper()
    return f"SCA-{now:%Y%m%d-%H%M}-{digest}"


def _risk_basis(payload: Dict[str, Any]) -> str:
    if payload.get("key_verified"):
        return "猜測金鑰已與相同長度的已知金鑰完整吻合，顯示本次資料可重現 CSP 洩漏。"
    if payload.get("known_key_total_bytes"):
        return (
            f"已知金鑰比對為 {payload.get('known_key_correct_bytes', 0)}/"
            f"{payload.get('known_key_total_bytes')} bytes，尚不足以宣告完整還原。"
        )
    if payload.get("key_hex"):
        return "攻擊已產生金鑰猜測，但未提供相同長度的已知金鑰，因此結果仍待驗證。"
    return "本次輸出屬洩漏診斷結果，未直接證明 CSP 已遭完整還原。"


def _assessment(payload: Dict[str, Any]) -> str:
    if payload.get("key_verified"):
        return "疑似不符合 - 待正式測試確認"
    if (payload.get("known_key_correct_bytes") or 0) > 0:
        return "發現部分洩漏跡象 - 待擴充樣本確認"
    return "證據不足 - 未判定"


def _baseline_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    now = _now_taipei()
    aes_version = str(payload.get("aes_version") or "未提供")
    methods = payload.get("attack_methods") or ["未提供"]
    method_text = ", ".join(str(item).upper() for item in methods)
    risk_level = str(payload.get("risk_level") or "待驗證（Unverified）")
    restore_status = str(payload.get("key_restore_status") or "未提供")
    product_name = str(payload.get("product_name") or "未提供")
    target_name = str(payload.get("target_name") or "未提供")
    test_organization = str(payload.get("test_organization") or "未提供")

    recommendations = [
        {
            "priority": "P1",
            "title": "導入 Masking 並驗證遮罩品質",
            "action": "針對 AES S-Box 與中間值導入至少一階遮罩，確認遮罩亂數品質及中間值不被編譯器重新合併。",
            "rationale": "降低中間值與功耗之間的統計相依性，直接緩解 CPA/DPA 類攻擊。",
        },
        {
            "priority": "P1",
            "title": "以 Hiding 降低可對齊洩漏",
            "action": "搭配隨機延遲、指令重排、時脈抖動或電流平衡；重新擷取波形確認對齊後仍無顯著洩漏。",
            "rationale": "增加 trace 對齊與統計聚合的難度，但不應單獨取代 Masking。",
        },
        {
            "priority": "P2",
            "title": "建立 ISO/IEC 17825 測試證據",
            "action": "保存設備、韌體版本、量測鏈、取樣率、觸發方式、trace 選取規則、前處理參數、腳本版本與原始輸出。",
            "rationale": "提升結果可重現性，並為合格實驗室的正式測試與差距分析提供證據。",
        },
        {
            "priority": "P2",
            "title": "擴充樣本並執行負向驗證",
            "action": "增加 trace 數量、重複不同裝置與環境條件，並使用已知金鑰與獨立資料集確認是否可穩定重現。",
            "rationale": "避免將偶然相關、過度擬合或資料品質問題誤判為可利用洩漏。",
        },
    ]

    return {
        "title": "晶片旁通道攻擊安全分析報告",
        "document_id": _document_id(payload, now),
        "generated_at": now.isoformat(timespec="seconds"),
        "generation_mode": "template",
        "ai_model": None,
        "standard": {
            "title": STANDARD_TITLE,
            "primary_clause": STANDARD_CLAUSE,
            "reference": "ISO/IEC 17825:2016",
        },
        "executive_summary": (
            f"本次以 {method_text} 分析 {aes_version} 功耗波形。{_risk_basis(payload)}"
            "本結果屬工程技術分析，不等同 ISO/IEC 17025 認證實驗室簽發的正式測試報告，"
            "亦不得單獨宣稱產品符合或不符合該標準。"
        ),
        "test_overview": [
            {"label": "產品／專案", "value": product_name},
            {"label": "待測晶片／模組", "value": target_name},
            {"label": "測試單位／人員", "value": test_organization},
            {"label": "AES 版本", "value": aes_version},
            {"label": "攻擊方式", "value": method_text},
            {"label": "Trace 數量", "value": f"{int(payload.get('num_traces') or 0):,}"},
            {"label": "採樣點／條", "value": f"{int(payload.get('trace_length') or 0):,}"},
            {"label": "攻擊耗時", "value": f"{float(payload.get('elapsed_seconds') or 0):.2f} 秒"},
            {"label": "金鑰還原", "value": restore_status},
        ],
        "risk": {
            "level": risk_level,
            "basis": _risk_basis(payload),
            "formal_compliance_status": "未判定（Not Determined）",
        },
        "findings": [
            {
                "id": "F-01",
                "title": f"{method_text} 旁通道分析結果",
                "severity": risk_level,
                "evidence": (
                    f"使用 {int(payload.get('num_traces') or 0):,} 條 trace、"
                    f"每條 {int(payload.get('trace_length') or 0):,} 個採樣點；"
                    f"金鑰還原狀態：{restore_status}。"
                ),
                "interpretation": _risk_basis(payload),
            }
        ],
        "standard_mapping": [
            {
                "clause": "5.1.1.3",
                "level": "3 級／選擇性要求（O）",
                "requirement": STANDARD_REQUIREMENT,
                "assessment": _assessment(payload),
                "evidence_gap": "仍需受控測試程序、已知金鑰驗證、重複性資料及合格實驗室判定。",
            },
            {
                "clause": "3.1–3.3",
                "level": "測試與驗證治理",
                "requirement": "正式測試應由通過 ISO/IEC 17025 認證的測試實驗室依標準程序執行並簽發報告。",
                "assessment": "本平台輸出僅供技術預評估",
                "evidence_gap": "尚未提供實驗室資格、正式測試計畫、校正紀錄與簽核資訊。",
            },
            {
                "clause": "引用標準",
                "level": "ISO/IEC 17825:2016",
                "requirement": "使用非侵入式攻擊緩解措施之測試方法建立可重現證據。",
                "assessment": "建議進一步驗證",
                "evidence_gap": "需依正式測試方法補齊設備、環境、資料處理及判定門檻。",
            },
        ],
        "recommendations": recommendations,
        "limitations": [
            "未提供完整待測物型號、韌體版本、量測設備、探棒、取樣率與環境條件時，結果不可跨裝置推論。",
            "若未提供相同長度的已知金鑰，金鑰猜測只能標示為待驗證，不可視為成功還原。",
            "單一演算法、單批 traces 與單次執行不足以形成正式符合性結論。",
            "AI 產生的敘述必須由具資格的人員覆核；量測事實與標準條文映射以平台固定欄位為準。",
        ],
        "disclaimer": (
            "本報告為 AI 輔助之工程分析紀錄，不是驗證證書，也不取代 ISO/IEC 17025 認證實驗室"
            "依 ISO/IEC 17825:2016 所執行的正式測試與簽發程序。"
        ),
    }


_AI_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "executive_summary": {"type": "string"},
        "finding_interpretation": {"type": "string"},
        "recommendations": {
            "type": "array",
            "minItems": 3,
            "maxItems": 6,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "priority": {"type": "string", "enum": ["P1", "P2", "P3"]},
                    "title": {"type": "string"},
                    "action": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["priority", "title", "action", "rationale"],
            },
        },
        "limitations": {"type": "array", "minItems": 3, "maxItems": 6, "items": {"type": "string"}},
    },
    "required": ["executive_summary", "finding_interpretation", "recommendations", "limitations"],
}


def _extract_gemini_text(response: Dict[str, Any]) -> str:
    candidates = response.get("candidates") or []
    if not candidates:
        feedback = response.get("promptFeedback") or {}
        raise RuntimeError(f"Gemini API 未回傳候選內容：{feedback}")
    parts = candidates[0].get("content", {}).get("parts", [])
    text_parts = [part.get("text") for part in parts if isinstance(part.get("text"), str)]
    if not text_parts:
        finish_reason = candidates[0].get("finishReason", "unknown")
        raise RuntimeError(f"Gemini API 未回傳可解析文字，finishReason={finish_reason}")
    return "".join(text_parts)


def _call_gemini(payload: Dict[str, Any], baseline: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("尚未設定 GEMINI_API_KEY")
    model = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
    base_url = os.getenv(
        "GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
    ).rstrip("/")

    safe_payload = {key: value for key, value in payload.items() if key != "plot_base64"}
    prompt = {
        "task": "撰寫防禦性晶片旁通道安全分析報告的敘述欄位",
        "facts": safe_payload,
        "fixed_standard_mapping": baseline["standard_mapping"],
        "fixed_risk": baseline["risk"],
        "constraints": [
            "使用繁體中文、正式且可稽核的語氣。",
            "不得改寫、臆測或補造任何量測數值、產品型號、實驗室資格或已知金鑰驗證結果。",
            "不得宣稱已通過認證、已符合標準或正式不符合；正式符合性狀態固定為未判定。",
            "明確引用 5.1.1.3、3.1–3.3 與 ISO/IEC 17825:2016 的角色。",
            "建議應包含 Masking、Hiding、S-Box／中間值防護、重測與證據保存。",
            "這是已授權的防禦性安全評估報告，不提供新的攻擊操作步驟。",
        ],
    }
    body = {
        "systemInstruction": {
            "parts": [
                {
                    "text": "你是晶片安全測試報告編輯，只能根據提供的事實撰寫，不得做正式認證判定。"
                }
            ]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": json.dumps(prompt, ensure_ascii=False)}],
            }
        ],
        "generationConfig": {
            "responseFormat": {
                "text": {
                    "mimeType": "application/json",
                    "schema": _AI_SCHEMA,
                }
            }
        },
    }
    body["generationConfig"]["responseFormat"]["text"]["mimeType"] = "APPLICATION_JSON"
    request = urllib.request.Request(
        f"{base_url}/models/{model}:generateContent",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"x-goog-api-key": api_key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:800]
        raise RuntimeError(f"Gemini API HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Gemini API 連線失敗：{exc.reason}") from exc

    narrative = json.loads(_extract_gemini_text(raw))
    narrative["model"] = model
    return narrative


def generate_security_report(payload: Dict[str, Any]) -> Dict[str, Any]:
    report = _baseline_report(payload)
    if not os.getenv("GEMINI_API_KEY", "").strip():
        report["ai_notice"] = "未設定 GEMINI_API_KEY，目前使用符合標準映射的固定模板。"
        return report

    try:
        narrative = _call_gemini(payload, report)
        report["executive_summary"] = narrative["executive_summary"]
        report["findings"][0]["interpretation"] = narrative["finding_interpretation"]
        report["recommendations"] = narrative["recommendations"]
        report["limitations"] = narrative["limitations"]
        report["generation_mode"] = "gemini"
        report["ai_model"] = narrative["model"]
        report["ai_notice"] = "敘述由 Google Gemini API 產生；量測事實、風險狀態與標準映射由程式固定。"
    except Exception as exc:
        report["ai_notice"] = f"Gemini 產生失敗，已安全退回固定模板：{str(exc)[:400]}"
    return report

def _register_cjk_font() -> str:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfbase.ttfonts import TTFont

    candidates = [
        ("MicrosoftJhengHei", r"C:\Windows\Fonts\msjh.ttc"),
        ("MicrosoftJhengHei", r"C:\Windows\Fonts\msjh.ttf"),
        ("NotoSansCJK", r"C:\Windows\Fonts\NotoSansCJK-Regular.ttc"),
    ]
    for name, path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                return name
            except Exception:
                pass
    pdfmetrics.registerFont(UnicodeCIDFont("MSung-Light"))
    return "MSung-Light"


def render_report_pdf(report: Dict[str, Any], plot_base64: str | None = None) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Image,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("尚未安裝 reportlab，請重新執行 start_platform.bat 安裝依賴") from exc

    font_name = _register_cjk_font()
    navy = colors.HexColor("#17233A")
    blue = colors.HexColor("#356AE6")
    pale_blue = colors.HexColor("#EEF4FF")
    pale_gray = colors.HexColor("#F5F7FA")
    border = colors.HexColor("#D9E0EA")
    warning = colors.HexColor("#9A5B00")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CJKTitle", fontName=font_name, fontSize=22, leading=30, textColor=navy, alignment=TA_CENTER, spaceAfter=8))
    styles.add(ParagraphStyle(name="CJKSubtitle", fontName=font_name, fontSize=10, leading=15, textColor=colors.HexColor("#64748B"), alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="CJKHeading", fontName=font_name, fontSize=14, leading=20, textColor=navy, spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="CJKBody", fontName=font_name, fontSize=9.4, leading=15, textColor=colors.HexColor("#263449"), alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="CJKSmall", fontName=font_name, fontSize=8, leading=12, textColor=colors.HexColor("#526177")))
    styles.add(ParagraphStyle(name="CJKWhite", fontName=font_name, fontSize=9, leading=13, textColor=colors.white))
    styles.add(ParagraphStyle(name="CJKRisk", fontName=font_name, fontSize=13, leading=19, textColor=warning, alignment=TA_CENTER))

    def para(value: Any, style: str = "CJKBody") -> Paragraph:
        text = str(value if value is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
        return Paragraph(text, styles[style])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=19 * mm,
        bottomMargin=18 * mm,
        title=str(report.get("title", "晶片旁通道攻擊安全分析報告")),
        author="SCA Platform",
        subject="AI-assisted defensive side-channel security analysis",
    )
    story: List[Any] = []

    story.append(Spacer(1, 16 * mm))
    story.append(para(report.get("title", "晶片旁通道攻擊安全分析報告"), "CJKTitle"))
    story.append(para("AI 輔助工程分析紀錄／非正式驗證證書", "CJKSubtitle"))
    story.append(Spacer(1, 10 * mm))
    cover_data = [
        [para("文件編號", "CJKSmall"), para(report.get("document_id", ""))],
        [para("產生時間", "CJKSmall"), para(report.get("generated_at", ""))],
        [para("主要標準", "CJKSmall"), para(report.get("standard", {}).get("title", STANDARD_TITLE))],
        [para("主要條文", "CJKSmall"), para(report.get("standard", {}).get("primary_clause", STANDARD_CLAUSE))],
        [para("正式符合性", "CJKSmall"), para(report.get("risk", {}).get("formal_compliance_status", "未判定"))],
    ]
    cover = Table(cover_data, colWidths=[38 * mm, 118 * mm], hAlign="CENTER")
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), pale_gray),
        ("GRID", (0, 0), (-1, -1), 0.5, border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(cover)
    story.append(Spacer(1, 12 * mm))
    risk_box = Table([[para(report.get("risk", {}).get("level", "待驗證"), "CJKRisk")]], colWidths=[156 * mm])
    risk_box.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8E8")), ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#E6B75A")), ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10)]))
    story.append(risk_box)
    story.append(Spacer(1, 12 * mm))
    story.append(para(report.get("disclaimer", ""), "CJKSmall"))
    story.append(PageBreak())

    story.append(para("1. 執行摘要", "CJKHeading"))
    story.append(para(report.get("executive_summary", "")))
    if report.get("ai_notice"):
        story.append(Spacer(1, 3 * mm))
        note = Table([[para(report["ai_notice"], "CJKSmall")]], colWidths=[156 * mm])
        note.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), pale_blue), ("BOX", (0, 0), (-1, -1), 0.5, blue), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story.append(note)

    story.append(para("2. 測試對象與分析條件", "CJKHeading"))
    overview = [[para("項目", "CJKWhite"), para("內容", "CJKWhite")]]
    overview.extend([[para(row.get("label", ""), "CJKSmall"), para(row.get("value", ""))] for row in report.get("test_overview", [])])
    table = Table(overview, colWidths=[43 * mm, 113 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale_gray]),
        ("GRID", (0, 0), (-1, -1), 0.4, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(table)

    story.append(para("3. 風險判定", "CJKHeading"))
    risk = report.get("risk", {})
    story.append(para(f"風險等級：{risk.get('level', '')}"))
    story.append(para(f"判定依據：{risk.get('basis', '')}"))
    story.append(para(f"正式符合性狀態：{risk.get('formal_compliance_status', '未判定')}"))

    story.append(para("4. 發現事項與證據", "CJKHeading"))
    for finding in report.get("findings", []):
        block = Table([
            [para(f"{finding.get('id', '')}｜{finding.get('title', '')}", "CJKWhite")],
            [para(f"嚴重度：{finding.get('severity', '')}")],
            [para(f"量測證據：{finding.get('evidence', '')}")],
            [para(f"解讀：{finding.get('interpretation', '')}")],
        ], colWidths=[156 * mm])
        block.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), blue),
            ("BOX", (0, 0), (-1, -1), 0.5, border),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether(block))
        story.append(Spacer(1, 3 * mm))

    if plot_base64:
        try:
            plot_bytes = base64.b64decode(plot_base64)
            image = Image(io.BytesIO(plot_bytes))
            image._restrictSize(156 * mm, 85 * mm)
            story.append(para("分析圖證", "CJKHeading"))
            story.append(image)
            story.append(para("圖 1：平台演算法輸出；應與原始資料、腳本版本及參數一併保存。", "CJKSmall"))
        except Exception:
            story.append(para("分析圖證無法解碼，未納入本次 PDF。", "CJKSmall"))

    story.append(para("5. 標準條文對照", "CJKHeading"))
    mapping = [[para("條文", "CJKWhite"), para("要求／定位", "CJKWhite"), para("本次評估", "CJKWhite")]]
    for row in report.get("standard_mapping", []):
        requirement = f"{row.get('level', '')}\n{row.get('requirement', '')}"
        assessment = f"{row.get('assessment', '')}\n\n證據缺口：{row.get('evidence_gap', '')}"
        mapping.append([para(row.get("clause", ""), "CJKSmall"), para(requirement, "CJKSmall"), para(assessment, "CJKSmall")])
    map_table = Table(mapping, colWidths=[24 * mm, 67 * mm, 65 * mm], repeatRows=1)
    map_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, pale_gray]),
        ("GRID", (0, 0), (-1, -1), 0.4, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(map_table)

    story.append(para("6. 安全強化建議", "CJKHeading"))
    for item in report.get("recommendations", []):
        story.append(KeepTogether([
            para(f"{item.get('priority', 'P2')}｜{item.get('title', '')}"),
            para(f"措施：{item.get('action', '')}"),
            para(f"理由：{item.get('rationale', '')}", "CJKSmall"),
            Spacer(1, 2.5 * mm),
        ]))

    story.append(para("7. 限制與後續驗證", "CJKHeading"))
    for index, item in enumerate(report.get("limitations", []), 1):
        story.append(para(f"{index}. {item}"))
        story.append(Spacer(1, 1.5 * mm))

    story.append(Spacer(1, 5 * mm))
    disclaimer = Table([[para(report.get("disclaimer", ""), "CJKSmall")]], colWidths=[156 * mm])
    disclaimer.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), pale_gray), ("BOX", (0, 0), (-1, -1), 0.5, border), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    story.append(disclaimer)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(border)
        canvas.line(17 * mm, 13 * mm, 193 * mm, 13 * mm)
        canvas.setFont(font_name, 7.5)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(17 * mm, 8.5 * mm, str(report.get("document_id", "SCA Report")))
        canvas.drawRightString(193 * mm, 8.5 * mm, f"第 {document.page} 頁")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()