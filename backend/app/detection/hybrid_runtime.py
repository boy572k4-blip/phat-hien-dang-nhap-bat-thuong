"""Nạp mô hình hybrid theo phiên bản đang active trong `model_registry`, chấm điểm luồng thật, fallback an toàn (MR12).

`HybridEngine.evaluate(features, hits)` là điểm vào duy nhất mà `app/detection/pipeline.py` gọi: luôn trả về một
`RiskResult` (không bao giờ raise), kể cả khi mô hình ML chưa nạp được (`ml_probability=None` — bộ gộp `combine_risk`
(MR11) đã coi đây là "không có bằng chứng đó", không phải "chắc chắn không", nên chỉ luật + danh tiếng vẫn hoạt động).

Nạp MỘT LẦN khi tiến trình khởi động (`app/main.py`, qua `get_engine()` singleton) — không nạp lại cho mỗi lần đăng nhập.
Nạp lỗi ở BẤT KỲ bước nào (thiếu hàng `model_registry`, thiếu file .joblib/.json, `feature_signature` lệch với bản đã
train) đều bị NUỐT và ghi log; khi đó dùng HỒ SƠ DỰ PHÒNG cứng (`_FALLBACK_PROFILE`, không có thành phần ML) để luật vẫn
được chấm điểm — "an toàn" ở đây nghĩa là KHÔNG BAO GIỜ tắt hẳn việc phát hiện chỉ vì mô hình lỗi."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

import joblib
from sqlalchemy.orm import Session

from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RiskResult, RuleWeights, combine_risk, geo_probability
from app.detection.model_registry import get_active
from ml.rba.features import feature_signature

logger = logging.getLogger("hybrid_runtime")

# Hồ sơ dự phòng khi chưa nạp được hồ sơ đã hiệu chỉnh (MR11) từ đĩa: bands rộng rãi, chỉ luật ghi đè + trọng số mặc
# định — vẫn cho điểm/hành động hợp lý (không phải "tắt hẳn"), chỉ là CHƯA hiệu chỉnh trên dữ liệu.
_FALLBACK_PROFILE = HybridProfile(RuleWeights(), ActionBands(alert_at=40, step_up_at=65, lock_at=85), ml_calibration=None)


@dataclass(frozen=True)
class MlAssessment:
    """Kết quả MỘT lần chạy mô hình cho một lần thử: xác suất đã hiệu chỉnh và tên thành phần `HybridMinTail` dẫn đầu.
    `None` ở từng trường nghĩa là không có bằng chứng đó (thiếu đặc trưng, mô hình chưa nạp, scorer không hỗ trợ, lỗi).
    `raw`: điểm thô (−log10 xác suất đuôi so với RBA) TRƯỚC khi trừ độ lệch miền (MR26) — để theo dõi sức khoẻ mô hình."""

    probability: float | None
    component: str | None
    raw: float | None = None


NO_ML = MlAssessment(probability=None, component=None)


def _attach_fast_isolation_forests(scorer) -> None:
    """Gắn bộ chấm Isolation Forest nhanh (trùng từng bit với sklearn, `ml/fast_iforest.py`) cho các thành phần
    Isolation Forest của mô hình vừa nạp. Thành phần nào không qua được kiểm tra trùng khớp thì giữ sklearn."""
    from ml.fast_iforest import build_verified

    for component in getattr(scorer, "components", ()):
        forest = getattr(component.scorer, "forest_", None)
        if forest is not None:
            fast = build_verified(forest)
            if fast is not None:
                component.scorer._fast_forest = fast


class HybridEngine:
    def __init__(self) -> None:
        self.profile: HybridProfile = _FALLBACK_PROFILE
        self.scorer = None  # frame -> điểm thô của hybrid_cp2 (ml.rba.ensemble.HybridMinTail), None nếu chưa nạp được
        self.model_name: str | None = None
        self.model_version: str | None = None

    @property
    def ml_available(self) -> bool:
        return self.scorer is not None and self.profile.ml_calibration is not None

    def load(self, db: Session) -> None:
        """Nạp phiên bản đang active trong `model_registry`. Không raise — lỗi bất kỳ bước nào thì giữ nguyên trạng thái
        trước đó (hoặc hồ sơ dự phòng nếu chưa từng nạp được gì)."""
        try:
            entry = get_active(db)
            if entry is None:
                logger.warning("model_registry chưa có phiên bản active — dùng hồ sơ dự phòng (chỉ luật + danh tiếng, không có ML)")
                return
            if entry.feature_signature is not None and entry.feature_signature != feature_signature():
                logger.warning(
                    "model_registry %s/%s train với feature_signature=%s nhưng mã hiện tại là %s — bỏ qua thành phần ML (đặc trưng đã đổi, cần train lại)",
                    entry.name, entry.version, entry.feature_signature, feature_signature(),
                )
                return
            scorer = joblib.load(entry.artifact_path)
            _attach_fast_isolation_forests(scorer)
            profile = HybridProfile.from_file(entry.profile_path) if entry.profile_path else HybridProfile(RuleWeights(), self.profile.bands, None)
            self.scorer, self.profile, self.model_name, self.model_version = scorer, profile, entry.name, entry.version
            logger.info("đã nạp mô hình hybrid %s/%s (ml_available=%s)", entry.name, entry.version, self.ml_available)
        except Exception:  # noqa: BLE001 — không được chặn khởi động ứng dụng vì mô hình lỗi
            logger.exception("lỗi khi nạp mô hình hybrid — dùng hồ sơ dự phòng (chỉ luật + danh tiếng)")

    def ml_assessment(self, features: dict[str, float] | None) -> MlAssessment:
        """Chạy mô hình MỘT lần, trả cả xác suất đã hiệu chỉnh lẫn thành phần dẫn đầu (MR13 dùng để gợi ý họ tấn công).
        Scorer không có `score_with_trigger` (hàm/lambda trần trong test) vẫn cho xác suất, thành phần là `None`.
        Không bao giờ raise: lỗi thì trả `NO_ML`."""
        if features is None or not self.ml_available:
            return NO_ML
        try:
            import pandas as pd

            frame = pd.DataFrame([features])
            if hasattr(self.scorer, "score_with_trigger"):
                raw_scores, names = self.scorer.score_with_trigger(frame)
                raw, component = raw_scores[0], str(names[0])
            else:
                raw, component = self.scorer(frame)[0], None
            success = features.get("cur_success") == 1.0
            return MlAssessment(probability=self.profile.ml_probability(float(raw), success), component=component, raw=float(raw))
        except Exception:  # noqa: BLE001
            logger.exception("lỗi khi chấm điểm ML — bỏ qua thành phần ML cho lần thử này")
            return NO_ML

    def ml_geo_probability(self, margin: float | None, slope: float | None) -> float | None:
        """MR22 — biên độ của mô hình địa lý-thời gian (tầng 3, `ml_model.predict()["margin"]`) -> xác suất nguồn `ml_geo`
        (`calibration.geo_probability`). Neo theo ngưỡng của NHÓM (`self.profile.bands`), không theo ngưỡng đã nới riêng
        của một tài khoản (MR15) — để việc nới ngưỡng vẫn giảm được cảnh báo do nguồn này gây ra. `None` khi không chấm
        (cold-start, chưa có mô hình/độ dốc). Không raise."""
        if margin is None or slope is None:
            return None
        try:
            return geo_probability(margin, slope, self.profile.bands)
        except Exception:  # noqa: BLE001
            logger.exception("lỗi khi đổi điểm tầng 3 sang xác suất — bỏ qua nguồn ml_geo cho lần thử này")
            return None

    def ml_probability(self, features: dict[str, float] | None) -> float | None:
        """Xác suất tấn công đã hiệu chỉnh (0-1) từ 50 đặc trưng RBA, `None` nếu thiếu đặc trưng hoặc mô hình chưa sẵn sàng."""
        return self.ml_assessment(features).probability

    def ml_component(self, features: dict[str, float] | None) -> str | None:
        """Tên thành phần của `HybridMinTail` (hybrid_cp2) có xác suất đuôi nhỏ nhất — `None` nếu thiếu đặc trưng, mô
        hình chưa sẵn sàng, scorer không hỗ trợ hoặc lỗi."""
        return self.ml_assessment(features).component

    def evaluate(
        self,
        features: dict[str, float] | None,
        hits: Iterable[RuleHit],
        *,
        bands: ActionBands | None = None,
        ml: MlAssessment | None = None,
        ml_geo: float | None = None,
        ml_geo_label: str | None = None,
    ) -> RiskResult:
        """Điểm 0-100 + hành động cho MỘT lần thử — không bao giờ raise (mọi lỗi rơi về `combine_risk` với `ml_probability=None`).

        `bands`: ngưỡng đã NỚI LỎNG riêng cho tài khoản đang chấm (MR15, `app/detection/adaptive_threshold.py` +
        `UserRiskProfile`) — `None` (mặc định) thì dùng thẳng ngưỡng NHÓM (`self.profile.bands`, hồ sơ hybrid đang
        active). Không ảnh hưởng `weights`/`ml_calibration` — MR15 chỉ chỉnh NGƯỠNG HÀNH ĐỘNG, không chỉnh lại cách
        tính điểm 0-100 (điểm hiển thị cho mọi người xem vẫn nhất quán; chỉ NGƯỠNG QUYẾT ĐỊNH hành động khác nhau).

        `ml`: kết quả `ml_assessment` đã tính sẵn cho chính lần thử này (pipeline cần thành phần dẫn đầu nên tính trước
        rồi truyền vào, tránh chạy mô hình lần thứ hai). `None` thì tự tính. `ml_geo` (MR22): xác suất của nguồn địa
        lý-thời gian (`ml_geo_probability`), `None` nếu không chấm; `ml_geo_label`: nhãn hiển thị của nguồn đó."""
        effective_bands = bands if bands is not None else self.profile.bands
        try:
            ml_probability = (ml if ml is not None else self.ml_assessment(features)).probability
        except Exception:  # noqa: BLE001 — phòng hờ kép, ml_assessment() đã tự bắt lỗi nhưng không đánh đổi độ an toàn
            ml_probability = None
        try:
            return combine_risk(
                ml_probability=ml_probability, hits=hits, weights=self.profile.weights, bands=effective_bands,
                ml_geo_probability=ml_geo, ml_geo_label=ml_geo_label,
            )
        except Exception:  # noqa: BLE001 — combine_risk là hàm thuần không nên lỗi, nhưng "không bao giờ raise" là bất biến của cả pipeline
            logger.exception("lỗi khi gộp điểm hybrid — coi như không có bằng chứng nào")
            return combine_risk(ml_probability=None, hits=(), weights=RuleWeights(), bands=effective_bands)


_engine: HybridEngine | None = None


def get_engine() -> HybridEngine:
    """Singleton trong tiến trình — nạp lần đầu gọi (nếu `app/main.py` chưa gọi `load_at_startup` trước)."""
    global _engine
    if _engine is None:
        _engine = HybridEngine()
    return _engine


def load_at_startup(db: Session) -> HybridEngine:
    engine = get_engine()
    engine.load(db)
    return engine
