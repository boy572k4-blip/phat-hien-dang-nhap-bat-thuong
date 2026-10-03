"""MR27 — hành vi nào "vững", đo trên bộ đánh giá MR24 (mở rộng ở MR27), đúng định nghĩa của giai đoạn I (docs/checklist.md):

    một hành vi VỮNG khi kịch bản tấn công của nó có cảnh báo nhờ CHÍNH tín hiệu của nó, và lưu lượng hợp lệ khó không vượt mục
    tiêu báo nhầm.

Đo cụ thể (ngưỡng đặt trước khi đo): với mỗi lần thử, chấm lại bằng `combine_risk` CHỈ với tín hiệu riêng của hành vi (các luật của
nó — tôn trọng chế độ shadow/enforce, hành động tối thiểu và cờ `forces` — và/hoặc nguồn mô hình nếu tín hiệu là mô hình).
  - phát hiện nhờ chính tín hiệu = tỉ lệ biến thể tấn công có ít nhất một lần thử độc hại đạt `alert` trở lên  → cần ≥ `MIN_OWN_DETECTION`
  - báo nhầm của chính tín hiệu = tỉ lệ lần thử của các họ hợp lệ mà riêng tín hiệu đó đạt `alert` trở lên        → cần ≤ `MAX_OWN_FP`
Kèm số "mọi nguồn" (cả hệ thống như đang chạy) để thấy hành vi không vững vẫn bị bắt nhờ tín hiệu khác hay không.

`--write`: thêm trọng số của luật mới `success_burst` (đo bằng đúng phương pháp MR25 trên bộ hiệu chỉnh) vào hồ sơ hybrid đang dùng;
các trọng số khác giữ nguyên số đo MR25.

    cd backend
    venv\\Scripts\\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr27
    venv\\Scripts\\python.exe -m ml.corpus.behaviors [--write]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from collections import defaultdict

from app.detection.engine.types import RuleHit
from app.detection.hybrid import HybridProfile, RuleWeights, combine_risk
from ml.corpus.calibrate_rules import CORPUS_DIR, PROFILE_PATH, calibrate, metrics, rule_hits

MR27_DIR = CORPUS_DIR / "mr27"
REPORT_PATH = MR27_DIR / "behaviors_report.json"
MIN_OWN_DETECTION = 0.5
MAX_OWN_FP = 0.01
NEW_RULES = ("success_burst",)

# hành vi -> (họ tấn công của bộ MR24, tín hiệu riêng[, kho IP của lần thử độc hại]). Tín hiệu: mã luật, "ml" (hybrid_cp2) hoặc "ml_geo"
# (mô hình địa lý-thời gian). Kho IP: chỉ tính biến thể mà lần thử độc hại đi qua kho đó (họ "ẩn danh" trộn Tor, VPN, datacenter).
BEHAVIORS: dict[str, tuple] = {
    "Dò mật khẩu một tài khoản": (("brute_force",), ("brute_force",)),
    "Nhồi thông tin đăng nhập": (("credential_stuffing",), ("credential_stuffing",)),
    "Rải mật khẩu chậm": (("password_spray_slow",), ("password_spray_slow",)),
    "Botnet phân tán (IP nước ngoài/ẩn danh)": (("distributed_botnet",), ("distributed_bruteforce",)),
    "Botnet phân tán cùng khu vực (IP Việt Nam)": (("distributed_botnet_local",), ("distributed_bruteforce",)),
    "Dò danh sách tài khoản": (("account_enumeration",), ("username_enumeration",)),
    "Thành công sau chuỗi sai": (("success_after_failures",), ("success_after_failures",)),
    "Xoay User-Agent": (("ua_rotation",), ("ua_rotation",)),
    "Nhịp thử đều như máy": (("regular_rhythm",), ("regular_rhythm",)),
    "Bot / client kịch bản": (("bot_client",), ("bot_user_agent", "scripted_client")),
    "Thử từ nhiều quốc gia": (("country_hop",), ("country_hop",)),
    "Đăng nhập qua Tor": (("anonymizer_login",), ("tor_exit",), ("tor",)),
    "Đăng nhập qua VPN/datacenter (một mình cố ý không cảnh báo, MR25)": (("anonymizer_login",), ("vpn_ip", "datacenter_ip"), ("vpn", "datacenter")),
    "Di chuyển bất khả thi": (("impossible_travel",), ("impossible_travel",)),
    "Đăng nhập thành công dồn dập": (("login_burst",), ("success_burst",)),
    "Tài khoản ngủ đông": (("dormant_account",), ("dormant_account_login", "ml_geo")),
    "Proxy cùng nước, nhà mạng lạ": (("same_country_proxy",), ("rare_network_login", "ml_geo")),
    "Mô phỏng tinh vi (mơ hồ có chủ đích)": (("targeted_mimic",), ("ml", "ml_geo")),
}


def load(split: str) -> list[dict]:
    with (MR27_DIR / f"{split}.jsonl").open(encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def own_action(step: dict, signals: tuple[str, ...], profile: HybridProfile) -> str:
    """Hành động khi CHỈ giữ tín hiệu riêng `signals` của lần thử (cùng `combine_risk`, cùng trọng số, ngưỡng, hành động tối thiểu)."""
    hits: list[RuleHit] = [h for h in rule_hits(step) if h.rule_id in signals]
    ml = profile.ml_probability(step["ml_raw"], step["success"]) if "ml" in signals and step.get("ml_raw") is not None else None
    geo = step.get("ml_geo") if "ml_geo" in signals else None
    return combine_risk(ml_probability=ml, ml_geo_probability=geo, hits=hits, weights=profile.weights, bands=profile.bands).action


def full_actions(records: list[dict], profile: HybridProfile) -> list[list[str]]:
    """Cả hệ thống như đang chạy: mọi luật, `hybrid_cp2` (đã trừ độ lệch miền MR26), `ml_geo`."""
    out = []
    for r in records:
        out.append([
            combine_risk(
                ml_probability=None if s.get("ml_raw") is None else profile.ml_probability(s["ml_raw"], s["success"]),
                ml_geo_probability=s.get("ml_geo"), hits=rule_hits(s), weights=profile.weights, bands=profile.bands,
            ).action
            for s in r["steps"]
        ])
    return out


def behavior_table(records: list[dict], profile: HybridProfile) -> list[dict]:
    benign_steps = [s for r in records if r["kind"] == "benign" for s in r["steps"]]
    full = dict(zip((r["id"] for r in records), full_actions(records, profile)))
    rows = []
    for name, spec in BEHAVIORS.items():
        families, signals, pools = spec[0], spec[1], (spec[2] if len(spec) > 2 else None)
        variants = [r for r in records if r["family"] in families
                    and (pools is None or any(s["malicious"] and s.get("pool") in pools for s in r["steps"]))]
        own = sum(any(s["malicious"] and own_action(s, signals, profile) != "allow" for s in r["steps"]) for r in variants)
        everything = sum(any(s["malicious"] and a != "allow" for s, a in zip(r["steps"], full[r["id"]])) for r in variants)
        fp = sum(own_action(s, signals, profile) != "allow" for s in benign_steps)
        fp_by_family, n_by_family = defaultdict(int), defaultdict(int)
        for r in records:
            if r["kind"] == "benign":
                for s in r["steps"]:
                    n_by_family[r["family"]] += 1
                    if own_action(s, signals, profile) != "allow":
                        fp_by_family[r["family"]] += 1
        worst = max(n_by_family, key=lambda f: fp_by_family[f] / n_by_family[f])
        own_rate, fp_rate = own / len(variants), fp / len(benign_steps)
        rows.append({
            "behavior": name, "families": list(families), "signals": list(signals), "variants": len(variants),
            "own_detection": round(own_rate, 3), "all_sources_detection": round(everything / len(variants), 3),
            "own_legit_alert_rate": round(fp_rate, 4), "own_legit_alerts": fp, "own_legit_by_family": dict(fp_by_family),
            "worst_legit_family": worst if fp_by_family[worst] else None,
            "worst_legit_family_rate": round(fp_by_family[worst] / n_by_family[worst], 4),
            "robust": own_rate >= MIN_OWN_DETECTION and fp_rate <= MAX_OWN_FP,
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="ghi trọng số của luật mới vào hồ sơ hybrid đang dùng")
    args = parser.parse_args()

    profile = HybridProfile.from_file(PROFILE_PATH)
    calibration, evaluation = load("calibration"), load("evaluation")
    measured = calibrate(calibration, profile.bands)
    new_entries = {rule: measured[rule] for rule in NEW_RULES if rule in measured}
    profile = dataclasses.replace(profile, weights=RuleWeights({**profile.weights.entries, **new_entries}, profile.weights.default_weight))

    rows = behavior_table(evaluation, profile)
    system = metrics(evaluation, full_actions(evaluation, profile))
    report = {
        "min_own_detection": MIN_OWN_DETECTION, "max_own_fp": MAX_OWN_FP,
        "new_rule_weights": {rule: e.to_dict() for rule, e in new_entries.items()},
        "behaviors": rows, "system": system,
    }
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    for rule, e in new_entries.items():
        print(f"trọng số {rule}: {e.weight:.3f} (đo trên bộ hiệu chỉnh, n = {e.n}, KTC {e.ci95[0]:.3f}–{e.ci95[1]:.3f}, {e.source})")
    print(f"{'hành vi':44s} {'riêng tín hiệu':>15s} {'mọi nguồn':>10s} {'báo nhầm riêng':>15s}  vững   họ hợp lệ bị báo nhiều nhất")
    for row in rows:
        worst = f"{row['worst_legit_family']} {row['worst_legit_family_rate']:.1%}" if row["worst_legit_family"] else "—"
        print(f"{row['behavior'][:44]:44s} {row['own_detection']:>15.0%} {row['all_sources_detection']:>10.0%} {row['own_legit_alert_rate']:>15.2%}  "
              f"{'✓' if row['robust'] else '✗'}    {worst}")
    print(f"vững {sum(r['robust'] for r in rows)}/{len(rows)} hành vi đo được trên bộ dữ liệu; cả hệ thống: hợp lệ bị cảnh báo "
          f"{system['legit_alert_rate']:.1%}, OTP/khoá {system['legit_step_up_or_lock_rate']:.2%}")
    if args.write and new_entries:
        current = HybridProfile.from_file(PROFILE_PATH)
        current = dataclasses.replace(current, weights=RuleWeights({**current.weights.entries, **new_entries}, current.weights.default_weight))
        current.save(PROFILE_PATH)
        print(f"đã ghi {', '.join(new_entries)} vào {PROFILE_PATH}")


if __name__ == "__main__":
    main()
