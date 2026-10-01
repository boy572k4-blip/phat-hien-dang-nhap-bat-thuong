"""Chấm điểm Isolation Forest nhanh cho vài dòng, kết quả GIỐNG HỆT `sklearn.ensemble.IsolationForest.score_samples`.

Vì sao cần: chấm MỘT lần đăng nhập, sklearn 1.6 tốn ~20-30 ms cho rừng 300 cây, gần như toàn bộ là chi phí điều phối
từng cây qua joblib (`Parallel` + `delayed`) và kiểm tra đầu vào của `tree.apply`; phần tính thật (đi từ gốc xuống lá)
chỉ vài micro-giây mỗi cây. Đo ở MR20: đây là phần lớn nhất còn lại của độ trễ `/login` sau khi sửa khối chiến dịch.

Thuật toán chép đúng `IsolationForest._compute_score_samples` của sklearn 1.6.0 (bản đang ghim trong
requirements.txt): ép kiểu float32 như `validate_data`, `tree_.apply` cho từng cây THEO ĐÚNG THỨ TỰ, cộng dồn
`decision_path_length + average_path_length - 1` theo cùng thứ tự nên tổng số thực trùng từng bit, rồi `2 ** (-depth/c)`.

Dựa vào thuộc tính nội bộ của sklearn (`_decision_path_lengths`, `_average_path_length_per_tree`, `_max_samples`,
`_max_features`). Vì vậy KHÔNG dùng trực tiếp: `build_verified()` so kết quả với sklearn trên một lô dòng thử ngay khi
nạp mô hình, lệch dù một bit thì trả `None` và nơi gọi tiếp tục dùng sklearn (chậm nhưng đúng)."""

from __future__ import annotations

import logging

import numpy as np
from sklearn.ensemble._iforest import _average_path_length

logger = logging.getLogger("fast_iforest")

_PROBE_ROWS = 128


class FastIsolationForest:
    def __init__(self, forest) -> None:
        self.offset_ = forest.offset_
        self.n_features_in_ = forest.n_features_in_
        self._trees = [estimator.tree_ for estimator in forest.estimators_]
        self._features = [np.asarray(features) for features in forest.estimators_features_]
        self._subsample = forest._max_features != forest.n_features_in_
        self._decision_path_lengths = forest._decision_path_lengths
        self._average_path_lengths = forest._average_path_length_per_tree
        self._denominator = len(forest.estimators_) * _average_path_length([forest._max_samples])

    def score_samples(self, X) -> np.ndarray:
        X = np.ascontiguousarray(X, dtype=np.float32)
        depths = np.zeros(X.shape[0], order="f")
        for tree, features, path_lengths, average_lengths in zip(self._trees, self._features, self._decision_path_lengths, self._average_path_lengths):
            leaves = tree.apply(X[:, features] if self._subsample else X)
            depths += path_lengths[leaves] + average_lengths[leaves] - 1.0
        scores = 2 ** (-np.divide(depths, self._denominator, out=np.ones_like(depths), where=self._denominator != 0))
        return -scores

    def decision_function(self, X) -> np.ndarray:
        return self.score_samples(X) - self.offset_


def build_verified(forest, *, seed: int = 0) -> FastIsolationForest | None:
    """`FastIsolationForest` nếu nó cho kết quả TRÙNG TỪNG BIT với `forest.score_samples` trên một lô dòng thử (giá
    trị ngẫu nhiên, dòng toàn 0, dòng có NaN), ngược lại `None`. Không bao giờ raise."""
    try:
        fast = FastIsolationForest(forest)
        rng = np.random.default_rng(seed)
        probe = rng.normal(scale=3.0, size=(_PROBE_ROWS, forest.n_features_in_))
        probe[0] = 0.0
        probe[1, ::2] = np.nan
        if np.array_equal(fast.score_samples(probe), forest.score_samples(probe), equal_nan=True):
            return fast
        logger.warning("chấm điểm Isolation Forest nhanh lệch với sklearn trên lô thử — dùng sklearn")
    except Exception:  # noqa: BLE001 — sklearn đổi nội bộ thì rơi về đường chậm nhưng đúng, không làm hỏng việc chấm
        logger.exception("không dựng được bộ chấm Isolation Forest nhanh — dùng sklearn")
    return None
