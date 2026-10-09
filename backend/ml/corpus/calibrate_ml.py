"""MR26 — hiệu chỉnh `hybrid_cp2` cho người dùng Việt Nam: độ lệch miền của điểm thô, không train lại mô hình.

Điểm thô của `hybrid_cp2` là −log10 xác suất đuôi so với đăng nhập hợp lệ CỦA RBA. Trên bộ MR24, đăng nhập THÀNH CÔNG hợp
lệ kiểu Việt Nam cao hơn RBA một khoảng gần như không đổi ở mọi phân vị — mô hình thấy "mạng Việt Nam" là hiếm, và các đặc
trưng độ hiếm toàn cục tính theo quy mô dữ liệu của chính hệ thống. Cách sửa (`MlDomainShift`):

    Δ_thành_công = Q_VN(q) − Q_RBA(q),   q = 1 − FPR mục tiêu của `alert` (99%, cùng mục tiêu MR11 dùng để đặt ngưỡng)

Q_VN: phân vị điểm thô của lần thử THÀNH CÔNG hợp lệ ở bộ hiệu chỉnh MR24; Q_RBA: phân vị (trọng số dân số) của đăng nhập
hợp lệ thành công ở val RBA — chính tập MR11 dùng để đặt ngưỡng. Lúc chấm: xác suất = đường hiệu chỉnh RBA(điểm thô − Δ).
Chỉ dùng lưu lượng HỢP LỆ (không dùng nhãn tấn công do nhóm tự dựng — fit thẳng isotonic trên bộ MR24 học luôn thiết kế của
bộ dữ liệu và làm mất 100% ATO trên RBA, đã đo). Δ của lần thất bại bị chặn ở 0: người dùng Việt Nam gõ sai có điểm THẤP hơn
RBA, và không làm mô hình nhạy hơn bản đã đo trên RBA. Trên chính RBA, Δ = 0 nên mọi số đo RBA giữ nguyên.

Khoảng tin cậy 95% của Δ: bootstrap theo biến thể. Đánh giá: phát lại bộ đánh giá MR24 qua `combine_risk` (luật đã khớp và
xác suất `ml_geo` ghi sẵn) với hồ sơ đang dùng, có và không có Δ.

    cd backend
    venv\\Scripts\\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr26
    venv\\Scripts\\python.exe -m ml.corpus.calibrate_ml            # in bảng, ghi ml/artifacts/corpus/mr26/mr26_report.json
    venv\\Scripts\\python.exe -m ml.corpus.calibrate_ml --write    # và ghi độ lệch miền vào hồ sơ hybrid đang dùng
"""

from __future__ import annotations

import argparse
import dataclasses
import json

import numpy as np

from app.detection.hybrid import HybridProfile, MlDomainShift, combine_risk
from ml.corpus.calibrate_rules import CORPUS_DIR, PROFILE_PATH, metrics, rule_hits

MR26_DIR = CORPUS_DIR / "mr26"
REPORT_PATH = MR26_DIR / "mr26_report.json"
ALERT_TARGET_FPR = 0.01  # = ml.rba.hybrid_calibrate.TARGET_FPR["alert_at"] (không import để khỏi nạp pandas/RBA khi chỉ chấm)
QUANTILE = 1 - ALERT_TARGET_FPR
N_BOOT = 500


def load(split: str) -> list[dict]:
    with (MR26_DIR / f"{split}.jsonl").open(encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def weighted_quantile(values: np.ndarray, weights: np.ndarray, q: float) -> float:
    order = np.argsort(values, kind="mergesort")
    cumulative = np.cumsum(weights[order]) / weights.sum()
    return float(values[order][min(np.searchsorted(cumulative, q), len(values) - 1)])


def legit_raw_by_variant(records: list[dict], success: bool) -> list[np.ndarray]:
    """Điểm thô của lần thử hợp lệ (họ hợp lệ) theo kết quả đăng nhập, gom theo biến thể (đơn vị bootstrap)."""
    out = []
    for r in records:
        if r["kind"] != "benign":
            continue
        raw = [s["ml_raw"] for s in r["steps"] if s.get("ml_raw") is not None and s["success"] == success]
        if raw:
            out.append(np.asarray(raw, dtype=float))
    return out


def estimate_shift(records: list[dict], rba_quantiles: dict[str, float], *, quantile: float = QUANTILE, n_boot: int = N_BOOT, seed: int = 0) -> MlDomainShift:
    """`rba_quantiles`: {"success": Q_RBA thành công, "failure": Q_RBA thất bại} ở cùng `quantile`."""
    by_variant = {kind: legit_raw_by_variant(records, kind == "success") for kind in ("success", "failure")}
    point = {kind: max(0.0, float(np.quantile(np.concatenate(v), quantile)) - rba_quantiles[kind]) for kind, v in by_variant.items()}
    rng = np.random.default_rng(seed)
    variants = by_variant["success"]
    boot = sorted(
        float(np.quantile(np.concatenate([variants[i] for i in rng.integers(0, len(variants), len(variants))]), quantile)) - rba_quantiles["success"]
        for _ in range(n_boot)
    )
    ci = (round(max(0.0, boot[int(0.025 * n_boot)]), 4), round(max(0.0, boot[int(0.975 * n_boot) - 1]), 4))
    return MlDomainShift(round(point["success"], 4), round(point["failure"], 4), quantile, "corpus_mr24", ci, int(sum(len(v) for v in variants)),
                         rba_quantiles.get("median_success"))


def rba_quantiles(quantile: float = QUANTILE) -> dict:
    """Q_RBA của đăng nhập hợp lệ ở val RBA (bỏ warm-up, không IP tấn công, không ATO), theo kết quả đăng nhập; cần dữ liệu RBA."""
    import joblib

    from ml.rba import hybrid_calibrate as H, models

    master = H.build_master_frame()
    hybrid = joblib.load(models.ARTIFACT_DIR / f"{H.HYBRID_NAME}.joblib")
    legit = master[(master["partition"] == "val") & ~master["in_warmup"] & ~master["is_attack_ip"].astype(bool) & ~master["is_ato"].astype(bool)]
    out = {}
    for kind, flag in (("success", 1), ("failure", 0)):
        rows = legit[legit["cur_success"] == flag]
        raw, weights = np.asarray(hybrid(rows), dtype=float), rows["pop_weight"].to_numpy()
        out[kind] = round(weighted_quantile(raw, weights, quantile), 4)
        out[f"median_{kind}"] = round(weighted_quantile(raw, weights, 0.5), 4)
        out[f"n_{kind}"] = int(len(rows))
    return out


def replay(records: list[dict], profile: HybridProfile, *, with_rules: bool = True, geo_cap: float | None = None) -> list[list[str]]:
    """Hành động từng lần thử qua đúng `combine_risk` với `profile` (độ lệch miền nằm trong hồ sơ). `with_rules=False`: chỉ
    `hybrid_cp2` (đo riêng báo nhầm do mô hình). `geo_cap`: phương án chặn `ml_geo` (chỉ để so sánh, không triển khai)."""
    out = []
    for r in records:
        actions = []
        for s in r["steps"]:
            ml = None if s.get("ml_raw") is None else profile.ml_probability(s["ml_raw"], s["success"])
            geo = s.get("ml_geo") if with_rules else None
            if geo is not None and geo_cap is not None:
                geo = min(geo, geo_cap)
            hits = rule_hits(s) if with_rules else []
            actions.append(combine_risk(ml_probability=ml, ml_geo_probability=geo, hits=hits, weights=profile.weights, bands=profile.bands).action)
        out.append(actions)
    return out


def _attack_mean(m: dict) -> float:
    rates = [v["rate"] for v in m["families"].values() if v["kind"] == "attack"]
    return round(sum(rates) / len(rates), 4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="ghi độ lệch miền vào hồ sơ hybrid đang dùng")
    args = parser.parse_args()

    profile = HybridProfile.from_file(PROFILE_PATH)
    calibration, evaluation = load("calibration"), load("evaluation")
    print("tính phân vị điểm thô của đăng nhập hợp lệ trên val RBA (vài phút) …", flush=True)
    rba_q = rba_quantiles()
    shift = estimate_shift(calibration, rba_q)
    without = dataclasses.replace(profile, ml_domain_shift=None)
    with_shift = dataclasses.replace(profile, ml_domain_shift=shift)
    vn_q = {kind: round(float(np.quantile(np.concatenate(legit_raw_by_variant(calibration, kind == "success")), QUANTILE)), 4) for kind in ("success", "failure")}

    geo_option = (profile.bands.alert_at - 1) / 100
    report = {
        "quantile": QUANTILE, "rba_quantiles": rba_q, "vn_quantiles": vn_q, "shift": shift.to_dict(),
        "evaluation": {
            "before": {"all_sources": metrics(evaluation, replay(evaluation, without)), "ml_only": metrics(evaluation, replay(evaluation, without, with_rules=False))},
            "after": {"all_sources": metrics(evaluation, replay(evaluation, with_shift)), "ml_only": metrics(evaluation, replay(evaluation, with_shift, with_rules=False))},
            "option_geo_alone_below_alert": {"geo_cap": geo_option, "all_sources": metrics(evaluation, replay(evaluation, with_shift, geo_cap=geo_option))},
        },
    }
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"phân vị {QUANTILE:.0%} điểm thô hợp lệ — RBA: thành công {rba_q['success']}, thất bại {rba_q['failure']}; "
          f"Việt Nam (bộ hiệu chỉnh): thành công {vn_q['success']}, thất bại {vn_q['failure']}")
    print(f"độ lệch miền: thành công Δ = {shift.success} (KTC 95% {shift.ci95_success[0]}–{shift.ci95_success[1]}), thất bại Δ = {shift.failure}")
    rows = (("trước", report["evaluation"]["before"]), ("sau", report["evaluation"]["after"]),
            ("phương án: ml_geo một mình < alert", report["evaluation"]["option_geo_alone_below_alert"]))
    for label, e in rows:
        a = e["all_sources"]
        ml = f" | chỉ hybrid_cp2: {e['ml_only']['legit_alert_rate']:.2%}" if "ml_only" in e else ""
        print(f"[{label}] hợp lệ bị cảnh báo {a['legit_alert_rate']:.1%}, OTP/khoá {a['legit_step_up_or_lock_rate']:.2%}, "
              f"phát hiện TB 15 họ {_attack_mean(a):.1%}{ml}")
    if args.write:
        with_shift.save(PROFILE_PATH)
        print(f"đã ghi độ lệch miền vào {PROFILE_PATH}")


if __name__ == "__main__":
    main()
