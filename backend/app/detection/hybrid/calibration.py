"""Cấu hình đã hiệu chỉnh của hybrid risk engine (MR11): xác suất luật, đường cong hiệu chỉnh mô hình ML, ngưỡng hành động.

Mọi kiểu ở đây chỉ là DỮ LIỆU (đọc/ghi JSON, kiểm tra hợp lệ) — việc TÍNH ra chúng từ RBA nằm ở `ml/rba/hybrid_calibrate.py`
(mirror của `app/detection/engine/registry.RuleConfig` <- `ml/rba/rule_tuning.py`). `combine.py` dùng các kiểu này để chấm.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import numpy as np

ACTIONS = ("allow", "alert", "step_up", "lock")
ACTION_RANK = {action: rank for rank, action in enumerate(ACTIONS)}  # so sánh "nặng hơn": lock > step_up > alert > allow
DEFAULT_WEIGHT = 0.05  # chưa hiệu chỉnh được trên RBA (xem RuleWeights.weight_of): coi là bằng chứng YẾU, không phải "không có ý nghĩa"


class HybridConfigError(ValueError):
    """Hồ sơ hybrid risk engine sai định dạng hoặc ngoài khoảng hợp lệ."""


@dataclass(frozen=True)
class MonotonicCalibrator:
    """Hàm bậc thang tuyến tính từng đoạn, ĐƠN ĐIỆU KHÔNG GIẢM: điểm thô của mô hình -> xác suất tấn công đã hiệu chỉnh.

    Học bằng hồi quy isotonic trên val (`ml.rba.ensemble.IsotonicCalibrator`, MR6) rồi xuất lại thành một dãy điểm gãy
    (`xs`, `ys`) — nội suy tuyến tính giữa các điểm gãy xấp xỉ rất sát hàm bậc thang gốc nhưng không cần scikit-learn hay
    tệp .joblib lúc chấm điểm thật (chỉ JSON thuần + numpy, giống triết lý `RuleConfig` của rule engine)."""

    xs: tuple[float, ...]
    ys: tuple[float, ...]

    def __post_init__(self) -> None:
        if len(self.xs) != len(self.ys) or len(self.xs) < 2:
            raise HybridConfigError("cần ít nhất 2 điểm gãy, xs và ys phải cùng độ dài")
        if any(b <= a for a, b in zip(self.xs, self.xs[1:])):
            raise HybridConfigError("xs phải tăng NGẶT")
        if any(b < a for a, b in zip(self.ys, self.ys[1:])):
            raise HybridConfigError("ys phải không giảm (đơn điệu) — hàm phải luôn tăng hoặc giữ nguyên")
        if min(self.ys) < 0.0 or max(self.ys) > 1.0:
            raise HybridConfigError("ys phải nằm trong [0, 1] (là xác suất)")

    def probability(self, scores):
        """Nội suy `xs -> ys`; ngoài hai đầu thì giữ nguyên giá trị biên (không ngoại suy). Nhận số hoặc mảng, trả đúng kiểu đó."""
        scalar = np.isscalar(scores)
        values = np.clip(np.interp(np.atleast_1d(np.asarray(scores, dtype=float)), self.xs, self.ys, left=self.ys[0], right=self.ys[-1]), 0.0, 1.0)
        return float(values[0]) if scalar else values

    def to_dict(self) -> dict[str, Any]:
        return {"xs": list(self.xs), "ys": list(self.ys)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MonotonicCalibrator":
        try:
            return cls(tuple(float(x) for x in data["xs"]), tuple(float(y) for y in data["ys"]))
        except (KeyError, TypeError) as exc:
            raise HybridConfigError(f"đường hiệu chỉnh sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class RuleWeightEntry:
    """Trọng số của MỘT luật: xác suất coi lần khớp của luật này là tấn công NẾU CHỈ MỘT MÌNH nó xuất hiện (dùng làm p_i
    trong noisy-OR — xem `combine.noisy_or`). `calibrated=False` nghĩa là đo được trên RBA (ví dụ luật cần IP/danh sách
    thật mà RBA không có) nên `weight` chỉ là giá trị đặt trước (`DEFAULT_WEIGHT`), không phải số đo."""

    weight: float
    calibrated: bool
    n: int = 0  # số dòng luật khớp dùng để đo (0 nếu calibrated=False)
    ci95: tuple[float, float] | None = None
    # MR25: nguồn của số đo — "rba" (MR11, độ chính xác trên RBA), "corpus_mr24" (tỉ số khả năng trên bộ dữ liệu hiệu
    # chỉnh MR24 quy về tỉ lệ tấn công của RBA), None với hồ sơ cũ (coi như "rba" nếu calibrated)
    source: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise HybridConfigError(f"trọng số {self.weight} phải trong [0, 1]")
        if self.n < 0:
            raise HybridConfigError("n phải >= 0")
        if self.ci95 is not None and self.ci95[0] > self.ci95[1]:
            raise HybridConfigError("ci95 phải là (thấp, cao) với thấp <= cao")

    def to_dict(self) -> dict[str, Any]:
        data = {"weight": self.weight, "calibrated": self.calibrated, "n": self.n, "ci95": None if self.ci95 is None else list(self.ci95)}
        if self.source is not None:
            data["source"] = self.source
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleWeightEntry":
        try:
            ci = data.get("ci95")
            return cls(
                float(data["weight"]), bool(data["calibrated"]), int(data.get("n", 0)), None if ci is None else (float(ci[0]), float(ci[1])),
                data.get("source"),
            )
        except (KeyError, TypeError, IndexError) as exc:
            raise HybridConfigError(f"trọng số luật sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class RuleWeights:
    """Trọng số của mọi luật + trọng số mặc định cho luật không có trong `entries`.

    MR21: bỏ danh sách "luật ghi đè" (`override_rule_ids`, trước đây chỉ có `blocklist_hit`) — quyết định chắc chắn
    giờ là `min_action` khai báo ngay trên luật (`app/detection/engine/registry.py`), dùng chung cho mọi luật xác định.
    Hồ sơ cũ còn khoá `override_rule_ids` vẫn đọc được (khoá đó bị bỏ qua)."""

    entries: Mapping[str, RuleWeightEntry] = field(default_factory=dict)
    default_weight: float = DEFAULT_WEIGHT

    def __post_init__(self) -> None:
        if not 0.0 <= self.default_weight <= 1.0:
            raise HybridConfigError(f"trọng số mặc định {self.default_weight} phải trong [0, 1]")

    def weight_of(self, rule_id: str) -> float:
        entry = self.entries.get(rule_id)
        return self.default_weight if entry is None else entry.weight

    def to_dict(self) -> dict[str, Any]:
        return {"weights": {rule_id: entry.to_dict() for rule_id, entry in self.entries.items()}, "default_weight": self.default_weight}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuleWeights":
        try:
            entries = {rule_id: RuleWeightEntry.from_dict(entry) for rule_id, entry in data.get("weights", {}).items()}
            default_weight = float(data.get("default_weight", DEFAULT_WEIGHT))
        except (TypeError, AttributeError) as exc:
            raise HybridConfigError(f"trọng số luật sai định dạng: {exc}") from exc
        return cls(entries, default_weight)


@dataclass(frozen=True)
class ActionBands:
    """Ba điểm cắt trên thang 0–100 chia bốn hành động: dưới `alert_at` là `allow`; [alert_at, step_up_at) là `alert`
    (hiện trong bảng điều khiển, không cản người dùng); [step_up_at, lock_at) là `step_up` (yêu cầu xác thực thêm);
    từ `lock_at` trở lên là `lock` (khoá tạm). Một luật enforce có `min_action` có thể nâng hành động lên trên mức mà
    điểm tự nó đạt được (MR21, `combine.combine_risk`)."""

    alert_at: int
    step_up_at: int
    lock_at: int

    def __post_init__(self) -> None:
        for name, value in (("alert_at", self.alert_at), ("step_up_at", self.step_up_at), ("lock_at", self.lock_at)):
            if not 0 <= value <= 100:
                raise HybridConfigError(f"{name}={value} phải trong [0, 100]")
        if not self.alert_at < self.step_up_at < self.lock_at:
            raise HybridConfigError(f"cần alert_at < step_up_at < lock_at (nhận {self.alert_at}, {self.step_up_at}, {self.lock_at})")

    def classify(self, score: int) -> str:
        if score >= self.lock_at:
            return "lock"
        if score >= self.step_up_at:
            return "step_up"
        if score >= self.alert_at:
            return "alert"
        return "allow"

    def floor(self, action: str) -> int:
        """Điểm thấp nhất của `action` — điểm hiển thị được nâng lên mức này khi một luật ÉP hành động (MR21), để điểm và
        hành động không mâu thuẫn ("điểm 10 nhưng bị khoá")."""
        return {"allow": 0, "alert": self.alert_at, "step_up": self.step_up_at, "lock": self.lock_at}[action]

    def to_dict(self) -> dict[str, int]:
        return {"alert_at": self.alert_at, "step_up_at": self.step_up_at, "lock_at": self.lock_at}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActionBands":
        try:
            return cls(int(data["alert_at"]), int(data["step_up_at"]), int(data["lock_at"]))
        except (KeyError, TypeError) as exc:
            raise HybridConfigError(f"ngưỡng hành động sai định dạng: {exc}") from exc


def geo_probability(margin: float, slope: float, bands: ActionBands) -> float:
    """MR22 — biên độ của mô hình địa lý-thời gian (tầng 3: điểm bất thường của Isolation Forest − ngưỡng quyết định của
    chính mô hình, > 0 là bị gắn cờ) -> xác suất trên thang của hybrid (nguồn `ml_geo`, xem `combine_risk`).

    Đường logistic: ĐỘ DỐC `slope` học bằng hồi quy logistic trên điểm ngoài mẫu có nhãn (ml/train.py); MỐC neo ở ngưỡng
    `alert` của `bands` — biên độ 0 cho đúng `alert_at/100`, nên MỘT MÌNH nguồn này cảnh báo đúng khi mô hình gắn cờ (như
    alert `ml_anomaly` riêng trước MR22, sai khác chỉ ở làm tròn điểm). Không dùng thẳng xác suất hiệu chỉnh trên dữ liệu
    tự sinh: tỉ lệ bất thường ở đó cao hơn thực tế nhiều nên xác suất bị thổi phồng (đo ở docs/geo-model-integration.md mục 3).
    Bị chặn trên bởi `geo_cap(bands)`."""
    anchor = min(max(bands.alert_at / 100, 1e-6), 1 - 1e-6)
    z = slope * margin + math.log(anchor / (1 - anchor))
    probability = 1.0 / (1.0 + math.exp(-z)) if z > -700 else 0.0  # exp tràn số với z rất âm: xác suất coi như 0
    return min(probability, geo_cap(bands))


def geo_cap(bands: ActionBands) -> float:
    """Trần của nguồn `ml_geo`: 1 − (1 − step_up)/(1 − alert), không thấp hơn ngưỡng alert. Đó là mức mà gộp noisy-OR với
    MỘT bằng chứng khác tự nó đủ cảnh báo thì vừa chạm ngưỡng step_up — nghĩa là: một mình tầng 3 chỉ CẢNH BÁO; tầng 3
    cộng một tín hiệu độc lập đáng cảnh báo mới thành yêu cầu xác thực thêm; muốn khoá phải có bằng chứng mạnh hơn nữa.
    Với ngưỡng 32/58 của hồ sơ RBA: 0,382.

    Lý do không để trần sát `step_up_at` (bản đầu của MR22, đo qua pipeline thật): mô hình gắn cờ thì đa số ca nằm ngay ở
    trần, nên chỉ thêm 2–3% bằng chứng bất kỳ là thành step_up, và cộng nền ~0,2–0,3 của `hybrid_cp2` với IP Việt Nam (lệch
    phân phối đã biết, MR26) là thành KHOÁ — mô hình học trên dữ liệu tự sinh không được tự đẩy tới mức đó."""
    alert, step_up = bands.alert_at / 100, bands.step_up_at / 100
    if alert >= 1:
        return 1.0
    return max(alert, 1 - (1 - step_up) / (1 - alert))


@dataclass(frozen=True)
class MlDomainShift:
    """MR26 — độ lệch miền của điểm thô `hybrid_cp2` giữa người dùng hợp lệ RBA và người dùng hợp lệ của hệ thống triển khai.

    Điểm thô là −log10 "xác suất đuôi" so với đăng nhập hợp lệ CỦA RBA (`ml.rba.ensemble.HybridMinTail`). Đo trên bộ MR24:
    đăng nhập THÀNH CÔNG hợp lệ kiểu Việt Nam cao hơn RBA một khoảng gần như không đổi ở mọi phân vị (median → 99,5%: 1,6–1,9)
    — mạng/quốc gia Việt Nam cực hiếm trong RBA, và các đặc trưng độ hiếm toàn cục tính theo quy mô dữ liệu của CHÍNH hệ
    thống. Trừ đi độ lệch đó rồi mới qua đường hiệu chỉnh RBA (`MonotonicCalibrator`): không train lại mô hình, không đổi
    đường hiệu chỉnh — trên chính RBA độ lệch bằng 0 nên mọi số đo RBA giữ nguyên. Tách theo kết quả đăng nhập vì hai thành
    phần của mô hình chỉ chấm lần thành công (phân phối điểm hai nhóm khác hẳn nhau).

    `success`/`failure`: độ lệch trừ vào điểm thô (≥ 0 — không bao giờ làm mô hình NHẠY hơn bản đo trên RBA). `quantile`:
    phân vị dùng để so (1 − FPR mục tiêu của `alert`), `source`/`ci95_success`/`n_reference`: nguồn và độ tin cậy của số đo.
    `rba_median_success`: trung vị điểm thô của đăng nhập thành công hợp lệ ở RBA — trang sức khoẻ mô hình so với trung vị
    trên log thật để ước lượng lại độ lệch (trung vị: ổn định với vài trăm lượt, độ lệch đo được gần như không đổi theo phân vị)."""

    success: float = 0.0
    failure: float = 0.0
    quantile: float | None = None
    source: str | None = None
    ci95_success: tuple[float, float] | None = None
    n_reference: int = 0
    rba_median_success: float | None = None

    def __post_init__(self) -> None:
        for name, value in (("success", self.success), ("failure", self.failure)):
            if not math.isfinite(value) or value < 0:
                raise HybridConfigError(f"độ lệch miền '{name}' phải là số hữu hạn ≥ 0 (không làm mô hình nhạy hơn RBA)")

    def adjust(self, raw: float, success: bool) -> float:
        return raw - (self.success if success else self.failure)

    def to_dict(self) -> dict[str, Any]:
        return {"success": self.success, "failure": self.failure, "quantile": self.quantile, "source": self.source,
                "ci95_success": None if self.ci95_success is None else list(self.ci95_success), "n_reference": self.n_reference,
                "rba_median_success": self.rba_median_success}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MlDomainShift":
        try:
            ci = data.get("ci95_success")
            return cls(float(data.get("success", 0.0)), float(data.get("failure", 0.0)), data.get("quantile"), data.get("source"),
                       None if ci is None else (float(ci[0]), float(ci[1])), int(data.get("n_reference", 0)),
                       None if data.get("rba_median_success") is None else float(data["rba_median_success"]))
        except (TypeError, ValueError, IndexError, AttributeError) as exc:
            raise HybridConfigError(f"độ lệch miền sai định dạng: {exc}") from exc


@dataclass(frozen=True)
class HybridProfile:
    """Hồ sơ đầy đủ để chấm điểm: trọng số luật, ngưỡng hành động, đường hiệu chỉnh mô hình (None nếu chưa có/không dùng
    thành phần ML — `combine_risk` khi đó chỉ gộp luật và danh tiếng, giống triết lý "model không khả dụng thì bỏ qua,
    không chặn luồng" của `app/detection/ml_model.py`)."""

    weights: RuleWeights
    bands: ActionBands
    ml_calibration: MonotonicCalibrator | None = None
    ml_domain_shift: MlDomainShift | None = None  # MR26; None = điểm thô dùng thẳng (miền RBA)

    def ml_probability(self, raw: float, success: bool) -> float | None:
        """Điểm thô `hybrid_cp2` -> xác suất: trừ độ lệch miền (nếu có) rồi qua đường hiệu chỉnh RBA."""
        if self.ml_calibration is None:
            return None
        adjusted = raw if self.ml_domain_shift is None else self.ml_domain_shift.adjust(raw, success)
        return float(self.ml_calibration.probability(adjusted))

    def to_dict(self) -> dict[str, Any]:
        data = {"rule_weights": self.weights.to_dict(), "bands": self.bands.to_dict(), "ml_calibration": None if self.ml_calibration is None else self.ml_calibration.to_dict()}
        if self.ml_domain_shift is not None:
            data["ml_domain_shift"] = self.ml_domain_shift.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "HybridProfile":
        if not isinstance(data, Mapping) or set(data) - {"rule_weights", "bands", "ml_calibration", "ml_domain_shift"}:
            raise HybridConfigError("hồ sơ chỉ có khoá 'rule_weights', 'bands', 'ml_calibration', 'ml_domain_shift'")
        if "bands" not in data:
            raise HybridConfigError("hồ sơ thiếu khoá bắt buộc 'bands'")
        calibration, shift = data.get("ml_calibration"), data.get("ml_domain_shift")
        return cls(
            RuleWeights.from_dict(data.get("rule_weights", {})), ActionBands.from_dict(data["bands"]),
            None if calibration is None else MonotonicCalibrator.from_dict(calibration), None if shift is None else MlDomainShift.from_dict(shift),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "HybridProfile":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HybridConfigError(f"hồ sơ không phải JSON hợp lệ: {exc}") from exc
        return cls.from_dict(data)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=1) + "\n", encoding="utf-8", newline="\n")
