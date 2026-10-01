"""MR20 — ml/fast_iforest.py: bộ chấm Isolation Forest nhanh phải cho kết quả TRÙNG TỪNG BIT với sklearn, và tự rơi về
sklearn (trả None) khi không chứng minh được điều đó."""

import os

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from ml.fast_iforest import FastIsolationForest, build_verified


def _forest(max_features=1.0):
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 6))
    return IsolationForest(n_estimators=40, max_samples=128, max_features=max_features, random_state=0).fit(X)


def _rows(n_features, n=300):
    rng = np.random.default_rng(1)
    X = rng.normal(scale=3.0, size=(n, n_features))
    X[0] = 0.0
    X[1, ::2] = np.nan
    return X


@pytest.mark.parametrize("max_features", [1.0, 0.5])  # 0.5: mỗi cây chỉ nhìn một tập con đặc trưng (đường subsample)
def test_scores_are_bit_identical_to_sklearn(max_features):
    forest = _forest(max_features)
    X = _rows(forest.n_features_in_)
    fast = FastIsolationForest(forest)
    assert np.array_equal(fast.score_samples(X), forest.score_samples(X), equal_nan=True)
    assert np.array_equal(fast.decision_function(X), forest.decision_function(X), equal_nan=True)


def test_single_row_matches_too():
    forest = _forest()
    x = _rows(forest.n_features_in_)[5:6]
    assert FastIsolationForest(forest).score_samples(x)[0] == forest.score_samples(x)[0]


def test_build_verified_returns_the_fast_scorer_when_it_matches():
    assert isinstance(build_verified(_forest()), FastIsolationForest)


def test_build_verified_refuses_a_scorer_that_differs_by_one_ulp(monkeypatch):
    original = FastIsolationForest.score_samples
    monkeypatch.setattr(FastIsolationForest, "score_samples", lambda self, X: np.nextafter(original(self, X), np.inf))
    assert build_verified(_forest()) is None


def test_build_verified_never_raises_on_an_object_that_is_not_a_fitted_forest():
    assert build_verified(object()) is None


@pytest.mark.parametrize("artifact", ["hybrid_cp2", "tier3"])
def test_the_real_trained_forests_are_accelerated_without_changing_a_single_score(artifact):
    if artifact == "hybrid_cp2":
        from app.detection.model_registry import _ARTIFACT_PATH

        if not _ARTIFACT_PATH.is_file():
            pytest.skip("chưa có artifact hybrid_cp2")
        forest = next(c.scorer.forest_ for c in joblib.load(_ARTIFACT_PATH).components if hasattr(c.scorer, "forest_"))
    else:
        path = os.path.join("ml", "artifacts", "isolation_forest.joblib")
        if not os.path.isfile(path):
            pytest.skip("chưa train model tầng 3")
        forest = joblib.load(path)
    fast = build_verified(forest)
    assert fast is not None
    X = _rows(forest.n_features_in_, n=2000)
    assert np.array_equal(fast.score_samples(X), forest.score_samples(X), equal_nan=True)
