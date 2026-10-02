"""Hybrid risk engine (MR11): gộp điểm ML đã hiệu chỉnh, kết quả rule engine v2 (MR9-10) và danh tiếng hạ tầng thành một
điểm 0-100 và một hành động (allow/alert/step_up/lock).

    from app.detection.hybrid import ActionBands, HybridProfile, RuleWeights, combine_risk

    profile = HybridProfile.from_file("app/detection/hybrid/profiles/rba_calibrated.json")
    ml_probability = None if profile.ml_calibration is None else profile.ml_calibration.probability(raw_ml_score)
    result = combine_risk(ml_probability=ml_probability, hits=rule_engine_evaluation.hits, weights=profile.weights, bands=profile.bands)
    print(result.score, result.action, [c.source for c in result.contributions[:3]])

Cách hiệu chỉnh trọng số/ngưỡng từ RBA và số đo: `ml/rba/hybrid_calibrate.py`, tài liệu `docs/hybrid-risk-engine.md`.
Luồng thật: `app/detection/hybrid_runtime.py` (MR12). Hai nguồn ML: mô hình `hybrid_cp2` (RBA) và, từ MR22, mô hình địa
lý-thời gian (tầng 3) qua `geo_probability` — nguồn `ml_geo`.
"""

from app.detection.hybrid.calibration import (
    ACTIONS,
    ActionBands,
    HybridConfigError,
    HybridProfile,
    MonotonicCalibrator,
    RuleWeightEntry,
    RuleWeights,
    geo_cap,
    geo_probability,
)
from app.detection.hybrid.combine import GEO_LABEL, REPUTATION_CATEGORY, Contribution, RiskResult, combine_risk, noisy_or

__all__ = [
    "ACTIONS", "ActionBands", "Contribution", "GEO_LABEL", "HybridConfigError", "HybridProfile", "MonotonicCalibrator",
    "REPUTATION_CATEGORY", "RiskResult", "RuleWeightEntry", "RuleWeights", "combine_risk", "geo_cap", "geo_probability",
    "noisy_or",
]
