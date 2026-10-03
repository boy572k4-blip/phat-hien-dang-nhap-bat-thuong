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

Hai mô hình (MR22): `hybrid_cp2` và mô hình địa lý-thời gian (`ml_geo`) cùng nhìn thấy "thiết bị mới", "vị trí/quốc gia
mới" — không độc lập, noisy-OR giữa chúng sẽ đếm cùng một tín hiệu hai lần. Nên NHÓM ML lấy xác suất LỚN HƠN của hai mô
hình (coi như phụ thuộc hoàn toàn — cận dưới của "ít nhất một đúng"), rồi mới noisy-OR với luật và danh tiếng. Đo qua
pipeline thật: cộng noisy-OR thì bằng chứng dưới ngưỡng của tầng 3 chồng lên nền ~0,2–0,3 mà `hybrid_cp2` cho mọi IP Việt
Nam (lệch phân phối đã biết, MR26) và biến đăng nhập bình thường thành cảnh báo. Mô hình thua vẫn được liệt kê trong
`contributions` (cùng chiều, để giải thích) nhưng không đổi điểm.

Danh tiếng hạ tầng (MR25) gộp cùng cách — lấy MAX trong nhóm: Tor/datacenter/VPN/blocklist đều là thuộc tính của CÙNG MỘT
IP, không phải bằng chứng độc lập (bộ MR24: 43/56 lần thử hợp lệ qua VPN khớp CẢ `vpn_ip` lẫn `datacenter_ip` — nhà cung
cấp VPN thuê máy chủ ở trung tâm dữ liệu). Noisy-OR sẽ đếm "IP này của nhà cung cấp VPN" hai lần.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from app.detection.engine.registry import CATEGORIES, REGISTRY, RuleSpec
from app.detection.engine.types import RuleHit
from app.detection.hybrid.calibration import ACTION_RANK, ActionBands, RuleWeights

REPUTATION_CATEGORY = "Danh tiếng hạ tầng"
assert REPUTATION_CATEGORY in CATEGORIES  # lỗi sớm nếu ai đổi tên nhóm trong registry.py mà quên sửa ở đây (test cũng kiểm tra lại)
GEO_LABEL = "mô hình địa lý-thời gian"  # nhãn mặc định của nguồn `ml_geo` (MR22)


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
    """Một bằng chứng đã góp vào điểm. `source`: `"ml"` (mô hình hybrid_cp2), `"ml_geo"` (mô hình địa lý-thời gian, MR22)
    hoặc mã luật. `weight`: xác suất coi bằng chứng này đúng nếu chỉ một mình nó xuất hiện (p_i ở trên). `group`: `"ml"`
    (cả hai mô hình — trong nhóm này chỉ mô hình có `weight` lớn hơn được tính vào điểm) | `"rule"` | `"reputation"`."""

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
    ml_geo_probability: float | None = None  # MR22: nguồn địa lý-thời gian (tầng 3), None nếu không chấm (cold-start, chưa có mô hình)

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
    ml_geo_probability: float | None = None,
    ml_geo_label: str | None = None,
) -> RiskResult:
    """Chấm MỘT lần thử.

    `ml_probability`: xác suất tấn công ĐÃ HIỆU CHỈNH (0–1, ví dụ qua `MonotonicCalibrator.probability`), hoặc `None` nếu
    mô hình không khả dụng — bỏ qua thành phần này, không chặn luồng (cùng triết lý `app/detection/ml_model.py`).
    `ml_geo_probability` (MR22): nguồn thứ hai — mô hình địa lý-thời gian (tầng 3) qua `calibration.geo_probability`;
    `None` khi không chấm (tài khoản chưa qua cổng cold-start, chưa có mô hình). Gộp với `ml_probability` bằng max, không
    phải noisy-OR (xem docstring module). `ml_geo_label`: nhãn hiển thị của nguồn đó (mặc định `GEO_LABEL`; pipeline thêm
    các đặc trưng lệch nhiều nhất).
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
        # Hành động tối thiểu: chỉ luật enforce, và chỉ lần khớp được phép ép (`RuleHit.forces` — phạm vi ASN thì không, MR27);
        # nhiều luật cùng ép thì lấy mức NẶNG nhất (cùng mức: luật khớp trước).
        if spec is not None and spec.min_action is not None and not hit.is_shadow and hit.forces and ACTION_RANK[spec.min_action] > ACTION_RANK[forced_action]:
            forced_action, forced_by = spec.min_action, hit.rule_id

    rule_probability = noisy_or(rule_probs)
    reputation_probability = max(reputation_probs, default=0.0)  # cùng một IP: phụ thuộc, lấy max (docstring module)
    if ml_probability is not None:
        contributions.append(Contribution("ml", "mô hình học máy", float(ml_probability), "ml"))
    if ml_geo_probability is not None:
        contributions.append(Contribution("ml_geo", ml_geo_label or GEO_LABEL, float(ml_geo_probability), "ml"))

    models = [float(p) for p in (ml_probability, ml_geo_probability) if p is not None]
    ml_group = max(models) if models else None  # hai mô hình phụ thuộc nhau: lấy max, không noisy-OR (docstring module)
    probability = noisy_or([ml_group, rule_probability if rule_probs else None, reputation_probability if reputation_probs else None])
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
        ml_geo_probability=ml_geo_probability,
    )
