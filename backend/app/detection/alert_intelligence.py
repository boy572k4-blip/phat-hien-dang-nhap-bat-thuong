"""MR13 — "Cảnh báo thông minh v2": so lần đăng nhập với lịch sử tài khoản (novelty), gán họ tấn công GỢI Ý (không
khẳng định), chống trùng lặp và xếp hạng ưu tiên cho cảnh báo `hybrid_risk` (MR12). Đo bằng kịch bản có nhãn tự tạo
(RBA không có nhãn "họ tấn công", chỉ có ATO nhị phân — xem project_rba_dataset.md): `backend/scripts/alert_intelligence_sim.py`.

Các mảnh, cố ý THUẦN (không đụng DB) để test được không cần DB thật — orchestration (đọc/ghi `Alert`, tra cứu sự cố
đang mở) nằm ở `app/detection/pipeline.py`:
  1. `compute_novelty`       — khía cạnh MỚI so với lịch sử THÀNH CÔNG của tài khoản (quốc gia/nhà mạng/thiết bị).
  2. `suggest_attack_family` — GỢI Ý họ tấn công + độ tin cậy, từ bằng chứng DẪN ĐẦU của `RiskResult` (MR11).
  3. `priority_score`        — novelty × độ tin cậy × `User.importance`, dùng để sắp `GET /alerts`.
  4. `Incident`              — MR23: một sự cố = một cảnh báo; gộp các lần thử của cùng một sự cố (xem docstring lớp).
  5. `build_alert_message`   — câu tiếng Việt gộp tất cả, giữ ngắn gọn (D4: vẫn top-3 lý do như hybrid_risk hiện có).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Any, Iterable, Mapping

from app.detection.engine.registry import REGISTRY, RuleSpec
from app.detection.engine.types import RuleHit
from app.detection.hybrid import Contribution, RiskResult
from app.detection.hybrid.calibration import ACTION_RANK
from ml.rba.explain import COMPONENT_LABELS
from ml.rba.features import NULL_KEY, EventRecord, HistorySummary

# --------------------------------------------------------------------------------------------------------- novelty

_ATTR_LABELS = {"country": "quốc gia", "asn": "nhà mạng", "device": "thiết bị"}
_DEVICE_LABELS_VI = {"mobile": "di động", "desktop": "máy tính", "tablet": "máy tính bảng", "bot": "bot"}
# Thứ tự ưu tiên khi CHỈ chọn MỘT khía cạnh mới lạ đưa vào message (giữ ngắn gọn — xem build_alert_message); không ảnh
# hưởng priority_score (dùng SỐ LƯỢNG khía cạnh mới, không quan tâm khía cạnh nào).
_NOVELTY_PRIORITY = ("country", "asn", "device")


def _attr_value(event: EventRecord, attr: str) -> str | None:
    if attr == "country":
        return event.country
    if attr == "asn":
        return None if event.asn is None else f"AS{event.asn}"
    if attr == "device":
        if event.device_type in (None, "unknown"):
            return None  # "chưa rõ" không phải là một GIÁ TRỊ để so sánh mới/cũ
        return _DEVICE_LABELS_VI.get(event.device_type, event.device_type)
    raise ValueError(f"thuộc tính novelty không hợp lệ: {attr}")


@dataclass(frozen=True)
class NoveltyFact:
    """Một khía cạnh MỚI so với lịch sử thành công của tài khoản. Khác `new_country`/`new_asn`/`new_device` (nhị phân,
    `ml/rba/features.py`, dùng để TRAIN mô hình): ở đây kèm luôn GIÁ TRỊ quen thuộc nhất và ĐÃ DÙNG BAO NHIÊU LẦN, để
    viết được câu "lần đầu quốc gia này, trước đó dùng X N lần" — đúng bullet đầu của MR13 (docs/checklist.md)."""

    attribute: str  # "country" | "asn" | "device"
    new_value: str  # giá trị lần này
    usual_value: str | None  # giá trị hay gặp nhất trước đó (None nếu tài khoản có lần thành công nhưng chưa từng có giá trị thuộc tính này)
    usual_count: int  # số lần THÀNH CÔNG trước đó mang giá trị usual_value (0 nếu usual_value None)

    @property
    def text(self) -> str:
        label = _ATTR_LABELS[self.attribute]
        if self.usual_value is None:
            return f"lần đầu {label} này ({self.new_value})"
        return f"lần đầu {label} này ({self.new_value}), trước đó dùng {self.usual_value} {self.usual_count} lần"


def _usual_values(success_counts: Counter, attr: str) -> Counter:
    """Số lần THÀNH CÔNG theo GIÁ TRỊ HIỂN THỊ (`_attr_value`) từ bộ đếm theo `attr_key` của đặc tả MR3
    (`UserHistory.success_counts`), giữ thứ tự xuất hiện đầu tiên — khi hai giá trị dùng ngang nhau, `most_common` chọn
    giá trị xuất hiện trước, đúng như khi còn đếm trên danh sách sự kiện theo thời gian (trước MR20)."""
    values: Counter = Counter()
    for key, n in success_counts.items():
        if key == NULL_KEY:
            continue  # thiếu dữ liệu không phải là một giá trị để so sánh mới/cũ
        if attr == "asn":
            values[f"AS{key}"] += n
        elif attr == "device":
            if key != "unknown":
                values[_DEVICE_LABELS_VI.get(key, key)] += n
        else:
            values[key] += n
    return values


def compute_novelty(event: EventRecord, summary: HistorySummary) -> list[NoveltyFact]:
    """Mọi khía cạnh MỚI của `event` so với lịch sử THÀNH CÔNG của tài khoản — rỗng nếu tài khoản không tồn tại hoặc
    CHƯA từng đăng nhập thành công (khi đó mọi thứ đều "mới", so sánh không có ý nghĩa gì để nói)."""
    user = summary.user
    if user is None or user.n_success == 0:
        return []
    facts: list[NoveltyFact] = []
    for attr in _NOVELTY_PRIORITY:
        current = _attr_value(event, attr)
        if current is None:
            continue
        counts = _usual_values(user.success_counts[attr], attr)
        if counts.get(current, 0) > 0:
            continue  # đã từng thấy giá trị này — không phải novelty
        usual_value, usual_count = counts.most_common(1)[0] if counts else (None, 0)
        facts.append(NoveltyFact(attr, current, usual_value, usual_count))
    return facts


# ------------------------------------------------------------------------------------------------- gán họ tấn công

# 3 thành phần của HybridMinTail (ml/rba/ensemble.py, mô hình hybrid_cp2 đang active) -> nhãn tiếng Việt. TÁI DÙNG
# COMPONENT_LABELS của ml/rba/explain.py (MR8) thay vì định nghĩa lại — một cái tên không nên có hai bản dịch khác nhau.
ML_COMPONENT_FAMILY: dict[str, str] = dict(COMPONENT_LABELS)
# MR22: khi bằng chứng dẫn đầu là mô hình địa lý-thời gian (tầng 3) chứ không phải hybrid_cp2. Mọi tên họ phải vừa cột
# `alerts.attack_family`/`campaigns.attack_family` (64 ký tự): bản MR22 dài 67 ký tự làm Postgres từ chối ghi cảnh báo — test
# chạy SQLite (không kiểm độ dài) nên không thấy, lộ ra khi đo độ trễ CP4 trên Postgres. test_alert_intelligence kiểm độ dài.
GEO_FAMILY = "đăng nhập bất thường về vị trí/thời gian"


def suggest_attack_family(
    risk_result: RiskResult, *, ml_component: str | None, registry: dict[str, RuleSpec] | None = None
) -> tuple[str | None, float | None]:
    """(họ tấn công GỢI Ý, độ tin cậy 0-1) từ bằng chứng DẪN ĐẦU của `risk_result.contributions` (đã sắp giảm dần theo
    trọng số — xem docstring `RiskResult`). `(None, None)` nếu không có bằng chứng nào (action="allow" thực tế không
    tạo alert nên nhánh này hiếm khi được gọi tới).

    Bằng chứng LUẬT/danh tiếng được ưu tiên hơn ML bất kể trọng số ai cao hơn — CỐ Ý, hai lý do: (1) nhất quán với
    `rule_id` (`app/detection/pipeline.py` đã chọn bằng chứng KHÔNG PHẢI "ml" đầu tiên cho `rule_id` từ MR12; family
    đi cùng nguồn với rule_id thì hai trường không "đá nhau" trên cùng một alert); (2) một luật có điều kiện khớp cụ
    thể, kiểm tra lại được LUÔN đáng tin hơn một điểm ML trên hệ thống demo — đo thật bằng
    backend/scripts/alert_intelligence_sim.py phát hiện: mô hình `hybrid_cp2` một mình có thể vượt ngưỡng "alert" chỉ
    vì ASN/quốc gia Việt Nam CỰC HIẾM so với phân bố huấn luyện RBA (đúng phát hiện PSI drift đã ghi ở MR12/docs/realtime-integration.md,
    ở đây thấy CỤ THỂ: nếu không ưu tiên luật, cảnh báo có luật rõ ràng như blocklist_hit sẽ bị gán nhầm thành "đăng
    nhập bất thường" chỉ vì lúc đó ML tình cờ có trọng số cao hơn). Chỉ dùng ML khi KHÔNG có bằng chứng luật/danh tiếng
    nào — khi đó CHÍNH bằng chứng duy nhất là ML nên không có lựa chọn nào đáng tin hơn để ưu tiên.

    LUÔN LÀ GỢI Ý: đây là MỘT LOOKUP đơn giản (nhóm luật đã khớp hoặc thành phần ML dẫn đầu), KHÔNG PHẢI một mô hình
    phân loại họ tấn công được huấn luyện riêng — chưa có nhãn "họ tấn công" thật để train (RBA chỉ có ATO nhị phân).
    Độ chính xác của gợi ý này được đo trên kịch bản có nhãn tự tạo (backend/scripts/alert_intelligence_sim.py), KHÔNG
    PHẢI trên ATO thật của RBA."""
    if not risk_result.contributions:
        return None, None
    registry = REGISTRY if registry is None else registry
    # MR23: luật đã ÉP hành động (MR21) là bằng chứng quyết định — họ tấn công theo nó, cùng nguồn với `rule_id`
    # (`Incident.rule_id`). Trước đó họ lấy bằng chứng trọng số cao nhất: các luật cùng trọng số mặc định 5% thì thứ tự
    # trong sổ đăng ký quyết định, nên một lần thử bị khoá vì blocklist vẫn có thể mang họ "dò mật khẩu" trong khi
    # `rule_id` là blocklist_hit.
    forced = registry.get(risk_result.overridden_by) if risk_result.overridden_by is not None else None
    if forced is not None:
        weight = next((c.weight for c in risk_result.contributions if c.source == forced.id), None)
        return forced.category, weight
    non_ml = [c for c in risk_result.contributions if c.group != "ml"]
    if non_ml:
        top = non_ml[0]  # contributions đã sắp giảm dần theo weight; lọc bỏ "ml" vẫn giữ đúng thứ tự giữa phần còn lại
        spec = registry.get(top.source)
        return (spec.category if spec is not None else None), top.weight
    top = risk_result.contributions[0]  # chỉ còn hai mô hình — mô hình dẫn đầu quyết định
    if top.source == "ml_geo":
        return GEO_FAMILY, top.weight
    family = ML_COMPONENT_FAMILY.get(ml_component or "") or "đăng nhập bất thường (mô hình học máy)"
    return family, top.weight


# ------------------------------------------------------------------------------------------------------- ưu tiên


def priority_score(novelty_facts: list[NoveltyFact], confidence: float | None, importance: float) -> float:
    """`novelty_level` (1 + số khía cạnh mới, tức 1..4) × độ tin cậy (0 nếu không rõ) × `importance` (User.importance,
    mặc định 1.0 mọi tài khoản). KHÔNG thay `severity`/`risk_score` (vẫn từ `RiskResult.score`, mục 4.2) — chỉ đổi THỨ
    TỰ hiển thị của `GET /alerts`: "lạ" và "nghiêm trọng" là hai trục khác nhau, một alert điểm không quá cao nhưng
    CỰC lạ (quốc gia+nhà mạng+thiết bị đều mới) đáng xem trước một alert điểm hơi cao hơn nhưng chẳng có gì mới."""
    novelty_level = 1 + len(novelty_facts)
    return round(novelty_level * (confidence or 0.0) * importance, 4)


# -------------------------------------------------------------------------------------------------- chống trùng lặp

# MR23: một lần thử đáng cảnh báo thuộc sự cố đang mở của cùng tài khoản (hoặc cùng IP nếu tài khoản không tồn tại) nếu
# cách lần GẦN NHẤT của sự cố đó không quá cửa sổ này — cửa sổ TRƯỢT (`Alert.last_seen_at`), không tính từ lần đầu. 15
# phút: đủ dài để gộp MỘT đợt tấn công liên tục (vd brute_force báo lại ở MỖI lần sai từ ngưỡng trở lên), đủ ngắn để
# không gộp hai đợt cách nhau hàng giờ — hằng số tự chọn từ MR13, chưa đối chiếu với dữ liệu tấn công thật (giới hạn ở
# docs/alert-intelligence-v2.md).
DEDUP_WINDOW = timedelta(minutes=15)

def action_escalated(previous_action: str, new_action: str) -> bool:
    """Có nên ghi thêm `response_actions`/`audit_log` khi CẬP NHẬT một alert đã gộp hay không: chỉ khi mức đề xuất
    TĂNG (vd alert -> lock) — không lặp lại đúng đề xuất cũ mỗi lần trùng, đúng tinh thần "chống trùng lặp"."""
    return ACTION_RANK.get(new_action, 0) > ACTION_RANK.get(previous_action, 0)


# ---------------------------------------------------------------------------------------------- sự cố (MR23)

_EVIDENCE_LIST_LIMIT = 20  # danh sách trong bằng chứng (vd các quốc gia) cắt bớt — cảnh báo không phải nơi lưu nhật ký


def json_safe(value: Any) -> Any:
    """Bằng chứng của luật (`RuleHit.evidence`) -> giá trị ghi được vào cột JSON: số không hữu hạn thành None, tuple/set
    thành danh sách (cắt `_EVIDENCE_LIST_LIMIT` phần tử), kiểu lạ thành chuỗi."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else list(value)
        return [json_safe(v) for v in items[:_EVIDENCE_LIST_LIMIT]]
    return str(value)


def evidence_of(hits: Iterable[RuleHit]) -> dict[str, dict]:
    """Chi tiết của MỌI luật đã khớp ở lần thử này (kể cả shadow), theo mã luật — để cảnh báo "liệt kê đủ bằng chứng"."""
    return {hit.rule_id: json_safe(dict(hit.evidence)) for hit in hits}


@dataclass(frozen=True)
class Incident:
    """MR23 — MỘT sự cố = MỘT cảnh báo. Sự cố là chuỗi lần thử bị đánh giá khác `allow` của cùng một tài khoản (hoặc cùng
    một IP khi tên đăng nhập không tồn tại), mỗi lần cách lần trước không quá `DEDUP_WINDOW` — BẤT KỂ họ tấn công của từng
    lần. Trước MR23 khoá gộp gồm cả họ tấn công và cửa sổ tính từ lần ĐẦU tiên, nên một cuộc tấn công đổi kiểu giữa chừng
    (dò mật khẩu -> đăng nhập thành công từ nơi khác) hoặc kéo dài quá 15 phút ra nhiều cảnh báo.

    Trạng thái của sự cố nằm ngay trong hàng `Alert` (cột + `explanation`) — `from_alert` dựng lại, `explanation()` ghi ra.
    Các trường `score`/`action`/`contributions`/`overridden_by` cùng tên với `RiskResult` để `build_alert_message` dùng
    chung cho cả một lần thử lẫn cả sự cố."""

    score: int  # điểm cao nhất trong sự cố
    action: str  # hành động nặng nhất
    overridden_by: str | None  # luật đã ép hành động nặng nhất (MR21); None nếu hành động đó đến từ điểm
    contributions: tuple[Contribution, ...]  # MỌI bằng chứng đã thấy: mỗi nguồn giữ trọng số lớn nhất, sắp giảm dần
    evidence: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)  # chi tiết theo luật, giữ lần gần nhất
    family: str | None = None  # họ tấn công gợi ý của lần thử QUYẾT ĐỊNH (điểm cao nhất)
    confidence: float | None = None
    occurrences: int = 1
    lead_rule: str | None = None  # luật dẫn đầu của lần thử quyết định (cùng lần thử với `family`)

    @staticmethod
    def _lead_rule_of(risk: RiskResult) -> str | None:
        return risk.overridden_by or next((c.source for c in risk.contributions if c.group != "ml"), None)

    @classmethod
    def start(cls, risk: RiskResult, *, family: str | None, confidence: float | None, evidence: Mapping[str, Mapping]) -> "Incident":
        return cls(
            score=risk.score, action=risk.action, overridden_by=risk.overridden_by, contributions=tuple(risk.contributions),
            evidence=dict(evidence), family=family, confidence=confidence, lead_rule=cls._lead_rule_of(risk),
        )

    def extend(self, risk: RiskResult, *, family: str | None, confidence: float | None, evidence: Mapping[str, Mapping]) -> "Incident":
        """Thêm một lần thử vào sự cố. Hành động chỉ tăng, không giảm; họ tấn công và luật dẫn đầu theo lần thử QUYẾT ĐỊNH
        — lần có điểm cao nhất (bằng nhau thì giữ lần trước); mỗi nguồn bằng chứng giữ trọng số lớn nhất từng thấy."""
        merged: dict[str, Contribution] = {c.source: c for c in self.contributions}
        for c in risk.contributions:
            if c.source not in merged or c.weight > merged[c.source].weight:
                merged[c.source] = c
        escalates = ACTION_RANK[risk.action] > ACTION_RANK[self.action]
        stronger = risk.score > self.score
        return replace(
            self,
            score=max(self.score, risk.score),
            action=risk.action if escalates else self.action,
            overridden_by=risk.overridden_by if escalates else self.overridden_by,
            contributions=tuple(sorted(merged.values(), key=lambda c: -c.weight)),
            evidence={**self.evidence, **evidence},
            family=family if stronger and family is not None else self.family,
            confidence=confidence if stronger and family is not None else self.confidence,
            occurrences=self.occurrences + 1,
            lead_rule=(self._lead_rule_of(risk) or self.lead_rule) if stronger else self.lead_rule,
        )

    @property
    def rule_id(self) -> str | None:
        """Luật đại diện cho `Alert.rule_id`: luật đã ép hành động nặng nhất, nếu không thì luật dẫn đầu của lần thử quyết
        định — không phải luật trọng số lớn nhất của cả sự cố: E2E TC1 (5 lần sai rồi đăng nhập được) phải đại diện bằng
        `success_after_failures`, lần thử làm sự cố lên `step_up`, không phải `brute_force` của các lần sai trước đó."""
        return self.overridden_by or self.lead_rule

    def explanation(self) -> dict[str, Any]:
        return {
            "contributions": [{"source": c.source, "label": c.label, "weight": round(c.weight, 4), "group": c.group} for c in self.contributions],
            "action": self.action,
            "forced_by": self.overridden_by,
            "lead_rule": self.lead_rule,
            "evidence": json_safe(self.evidence),
        }

    @classmethod
    def from_alert(cls, alert: Any) -> "Incident":
        """Dựng lại từ một hàng `Alert` đã lưu (thiếu khoá thì lấy giá trị an toàn — cảnh báo cũ trước MR23 vẫn đọc được)."""
        explanation = alert.explanation or {}
        contributions = tuple(
            Contribution(c.get("source", "?"), c.get("label", ""), float(c.get("weight", 0.0)), c.get("group", "rule"))
            for c in explanation.get("contributions", ())
        )
        return cls(
            score=int(alert.risk_score), action=explanation.get("action", "alert"), overridden_by=explanation.get("forced_by"),
            contributions=contributions, evidence=dict(explanation.get("evidence") or {}), family=alert.attack_family,
            confidence=alert.attack_family_confidence, occurrences=alert.occurrence_count or 1,
            lead_rule=explanation.get("lead_rule", getattr(alert, "rule_id", None)),
        )


# -------------------------------------------------------------------------------------------------------- message


def build_alert_message(
    risk_result: RiskResult | Incident, *, novelty_facts: list[NoveltyFact], family: str | None, confidence: float | None, occurrence_count: int = 1
) -> str:
    """Câu tiếng Việt cho `Alert.message`. D4 (quyết định cùng người dùng ở MR13): vẫn TOP-3 lý do như message
    `hybrid_risk` hiện có (MR12) — KHÔNG rút xuống top-2. Thêm nhiều nhất MỘT khía cạnh mới lạ (khía cạnh đầu theo
    `_NOVELTY_PRIORITY`, nói cả 3 thì quá dài cho danh sách cảnh báo — xem docstring `NoveltyFact`) và tên họ tấn công
    GỢI Ý kèm %, LUÔN kèm chữ "gợi ý" (không bao giờ khẳng định chắc chắn). Nhận một lần thử (`RiskResult`) hoặc cả sự cố
    (`Incident`, MR23: điểm cao nhất, hành động nặng nhất, bằng chứng gộp của mọi lần thử)."""
    reasons = "; ".join(f"{c.label} ({c.weight:.0%})" for c in risk_result.contributions[:3])
    parts = [f"Hybrid risk engine: điểm {risk_result.score}/100, đề xuất '{risk_result.action}' — {reasons}."]
    if risk_result.overridden_by is not None:
        # MR21: hành động đến từ "hành động tối thiểu" của một luật xác định, không phải từ điểm — luật đó có thể có trọng
        # số thấp (không lọt top-3 ở trên) nên phải nói rõ, nếu không người đọc không biết vì sao lại là mức này.
        spec = REGISTRY.get(risk_result.overridden_by)
        title = spec.title if spec is not None else risk_result.overridden_by
        parts.append(f"Mức '{risk_result.action}' là hành động tối thiểu của luật \"{title}\".")
    if novelty_facts:
        parts.append(novelty_facts[0].text[0].upper() + novelty_facts[0].text[1:] + ".")
    if family:
        conf_text = f" ({confidence:.0%})" if confidence is not None else ""
        parts.append(f"Họ tấn công gợi ý: {family}{conf_text}.")
    if occurrence_count > 1:
        parts.append(f"Sự cố gồm {occurrence_count} lần thử, mỗi lần cách lần trước không quá {int(DEDUP_WINDOW.total_seconds() // 60)} phút.")
    return " ".join(parts)
