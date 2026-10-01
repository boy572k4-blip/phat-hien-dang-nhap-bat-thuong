"""Hybrid risk engine (MR11): gộp xác suất ML đã hiệu chỉnh, kết quả luật và danh tiếng hạ tầng thành MỘT điểm 0–100 và
MỘT hành động — noisy-OR có trọng số, cộng HÀNH ĐỘNG TỐI THIỂU của luật xác định (MR21).

Vì sao noisy-OR chứ không phải "luật HOẶC mô hình" (gộp cảnh báo): MR10 (`docs/rule-ml-overlap.md`) đo trực tiếp trên RBA
rằng gộp kiểu "bất kỳ bên nào báo là báo" không tăng recall so với chỉ nới ngưỡng của một mình mô hình đến cùng tổng báo
nhầm — tăng báo nhầm mà không tăng phát hiện. Noisy-OR CÓ TRỌNG SỐ coi mỗi bằng chứng là một xác suất độc lập
(`RuleWeights`, hiệu chỉnh ở `ml/rba/hybrid_calibrate.py`): luật ồn (đa số các luật khi đứng một mình, theo MR10) tự động
đóng góp ít vì trọng số thấp, luật đáng tin đóng góp nhiều — không cần đặt tay "luật nào được tính".

Hành động tối thiểu (MR21, `RuleSpec.min_action`): trọng số là độ chính xác đo trên RBA — dữ liệu không có toạ độ, IP
giả, gần như không có bot nên nhiều luật xác định (di chuyển bất khả thi, dò mật khẩu...) không đo được hoặc đo trên mẫu
quá nhỏ và chỉ được 0–10%; chỉ 1/19 luật đủ trọng số để một mình vượt ngưỡng cảnh báo. Thay vì nâng trọng số bằng tay
(làm sai ý nghĩa "xác suất"), luật xác định khai báo mức hành động tối thiểu: khớp ở chế độ `enforce` thì hành động ít nhất
là mức đó. Điểm vẫn là xác suất của bằng chứng (`probability`), chỉ điểm HIỂN THỊ (`score`) được nâng lên ngưỡng thấp nhất
của hành động bị ép để điểm và hành động không mâu thuẫn. Tổng quát hoá cơ chế "ghi đè" trước đây chỉ có cho `blocklist_hit`
(giờ là `min_action="lock"`).

Chế độ của luật: `enforce` và `shadow` đều là bằng chứng có trọng số; chỉ `enforce` được ép hành động tối thiểu. Trước MR21
docstring này ghi "shadow chỉ quyết định RuleEngine có tự tạo cảnh báo hay không" — sai trên luồng thật, nơi RuleEngine
không tạo cảnh báo nào (đo ở docs/untested-behaviors-measured.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from app.detection.engine.registry import CATEGORIES, REGISTRY, RuleSpec
from app.detection.engine.types import RuleHit
from app.detection.hybrid.calibration import ACTION_RANK, ActionBands, RuleWeights

REPUTATION_CATEGORY = "Danh tiếng hạ tầng"
assert REPUTATION_CATEGORY in CATEGORIES  # lỗi sớm nếu ai đổi tên nhóm trong registry.py mà quên sửa ở đây (test cũng kiểm tra lại)


def noisy_or(probabilities: Iterable[float | None]) -> float:
    """Xác suất ÍT NHẤT MỘT bằng chứng đúng, coi các bằng chứng ĐỘC LẬP: 1 − Π(1 − p_i). `None` = không có bằng chứng đó,
    bị bỏ qua (không phải "chắc chắn không", khác 0.0). Danh sách rỗng hoặc toàn `None` trả 0.0 (không có bằng chứng nào).

    Phân rã đúng nghĩa (không phải xấp xỉ kiểu Shapley/z-score như MR8 dùng để giải thích mô hình ML): trong không gian
    log, log(1 − P) = Σ log(1 − p_i), nên đóng góp CHÍNH XÁC của bằng chứng thứ i vào (1 − P) là thừa số (1 − p_i), không
    phụ thuộc thứ tự cộng vào — `Contribution.weight` chính là p_i này."""
    complement = 1.0
    seen = False
    for p in probabilities:
        if p is None:
            continue
        seen = True
        complement *= 1.0 - min(max(float(p), 0.0), 1.0)
    return 1.0 - complement if seen else 0.0


@dataclass(frozen=True)
class Contribution:
    """Một bằng chứng đã góp vào điểm. `source`: `"ml"` hoặc mã luật. `weight`: xác suất coi bằng chứng này đúng nếu chỉ
    một mình nó xuất hiện (p_i ở trên). `group`: `"ml"` | `"rule"` | `"reputation"`."""

    source: str
    label: str
    weight: float
    group: str


@dataclass(frozen=True)
class RiskResult:
    """Kết quả chấm MỘT lần thử. `contributions` sắp theo `weight` giảm dần — dùng thẳng để giải thích cảnh báo (MR13):
    2–3 mục đầu là "vì sao" chính, đúng tinh thần đã đo độ trung thực ở MR8 (top-k là NGUYÊN NHÂN CHỦ ĐẠO, không phải
    toàn bộ lý do)."""

    score: int  # 0-100 hiển thị: round(probability*100), nâng lên ngưỡng của hành động nếu bị luật ép (xem docstring module)
    action: str  # một trong calibration.ACTIONS
    probability: float  # xác suất tấn công của bằng chứng (noisy-OR), KHÔNG bị nâng bởi hành động tối thiểu
    ml_probability: float | None
    rule_probability: float
    reputation_probability: float
    overridden_by: str | None  # mã luật đã ÉP hành động lên mức tối thiểu của nó (MR21); None nếu hành động đến từ điểm
    contributions: tuple[Contribution, ...]

    @property
    def is_overridden(self) -> bool:
        return self.overridden_by is not None


def combine_risk(
    *,
    ml_probability: float | None,
    hits: Iterable[RuleHit],
    weights: RuleWeights,
    bands: ActionBands,
    registry: Mapping[str, RuleSpec] | None = None,
) -> RiskResult:
    """Chấm MỘT lần thử.

    `ml_probability`: xác suất tấn công ĐÃ HIỆU CHỈNH (0–1, ví dụ qua `MonotonicCalibrator.probability`), hoặc `None` nếu
    mô hình không khả dụng — bỏ qua thành phần này, không chặn luồng (cùng triết lý `app/detection/ml_model.py`).
    `hits`: các luật đã khớp của MỘT lần thử (`Evaluation.hits` — gồm cả luật `shadow`: vẫn là bằng chứng có trọng số,
    chỉ không được ép hành động tối thiểu, xem docstring module)."""
    registry = REGISTRY if registry is None else registry
    rule_probs: list[float] = []
    reputation_probs: list[float] = []
    contributions: list[Contribution] = []
    forced_action, forced_by = "allow", None
    seen: set[str] = set()

    for hit in hits:
        if hit.rule_id in seen:  # engine chỉ khớp tối đa 1 lần/luật/lần thử; phòng hờ khi gọi trực tiếp với dữ liệu tuỳ ý
            continue
        seen.add(hit.rule_id)
        weight = weights.weight_of(hit.rule_id)
        spec = registry.get(hit.rule_id)
        is_reputation = spec is not None and spec.category == REPUTATION_CATEGORY
        (reputation_probs if is_reputation else rule_probs).append(weight)
        contributions.append(Contribution(hit.rule_id, hit.message, weight, "reputation" if is_reputation else "rule"))
        # Hành động tối thiểu: chỉ luật enforce; nhiều luật cùng ép thì lấy mức NẶNG nhất (cùng mức: luật khớp trước).
        if spec is not None and spec.min_action is not None and not hit.is_shadow and ACTION_RANK[spec.min_action] > ACTION_RANK[forced_action]:
            forced_action, forced_by = spec.min_action, hit.rule_id

    rule_probability = noisy_or(rule_probs)
    reputation_probability = noisy_or(reputation_probs)
    if ml_probability is not None:
        contributions.append(Contribution("ml", "mô hình học máy", float(ml_probability), "ml"))

    probability = noisy_or([ml_probability, rule_probability if rule_probs else None, reputation_probability if reputation_probs else None])
    score = min(100, max(0, round(probability * 100)))
    action = bands.classify(score)
    overridden_by = None
    if ACTION_RANK[forced_action] > ACTION_RANK[action]:  # luật ép mức nặng hơn mức điểm tự đạt -> theo luật, nâng điểm hiển thị
        action, overridden_by = forced_action, forced_by
        score = max(score, bands.floor(action))
    contributions.sort(key=lambda c: -c.weight)
    return RiskResult(
        score=score, action=action, probability=probability, ml_probability=ml_probability, rule_probability=rule_probability,
        reputation_probability=reputation_probability, overridden_by=overridden_by, contributions=tuple(contributions),
    )
