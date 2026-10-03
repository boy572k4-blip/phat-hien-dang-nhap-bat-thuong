"""MR25 — hiệu chỉnh lại trọng số luật trên bộ dữ liệu hiệu chỉnh (MR24), báo số trên bộ đánh giá.

Trọng số của luật là P(tấn công | luật khớp) dùng trong noisy-OR (MR11). Trên RBA, MR11 đo bằng ĐỘ CHÍNH XÁC của luật — ở đó tỉ
lệ tấn công là của chính dữ liệu (8,4% lần thử ở bộ val, có trọng số). Bộ MR24 có tỉ lệ tấn công do NHÓM chọn (~70% lần thử),
nên độ chính xác thô sẽ thổi phồng trọng số. Thay vào đó đo TỈ SỐ KHẢ NĂNG
    LR = P(luật khớp | lần thử độc hại) / P(luật khớp | lần thử hợp lệ)        (cộng 0,5 vào mỗi ô — tránh chia cho 0)
rồi quy về CÙNG thang với trọng số RBA:  w = π·LR / (π·LR + 1 − π),  π = `RBA_ATTACK_PRIOR`.
Khoảng tin cậy 95%: bootstrap theo BIẾN THỂ (các lần thử trong một biến thể không độc lập), lấy mẫu lại riêng từng loại.

Luật đo hợp lệ trên RBA (`RBA_VALID`) GIỮ trọng số RBA; luật RBA không đo được (mặc định 5%) hoặc ra 0% do mẫu quá nhỏ/RBA
làm nhiễu quốc gia-thời gian được đo lại ở đây.

Hai trần, cùng kiểu trần 0,382 của `ml_geo` (MR22) — đặt theo ngưỡng hành động, không phải số tự chọn:
- MỌI trọng số đo trên bộ này ≤ ngay dưới `step_up`: một mình luật chỉ đủ CẢNH BÁO, muốn bắt xác thực thêm/khoá phải có thêm
  bằng chứng độc lập (hoặc `min_action`). Lý do: nhiều luật không khớp lần thử hợp lệ nào, nên LR chỉ bị chặn bởi cỡ mẫu
  (~1.300 lần thử hợp lệ, cộng 0,5) và ra ~0,95 — con số đó nói "luật mạnh trên kịch bản nhóm tự dựng", không nói được báo
  nhầm thật dưới 1/1.300; để nguyên thì MỘT luật (vd di chuyển bất khả thi — VPN bật/tắt là nguồn báo nhầm kinh điển) tự KHOÁ.
- `CONTEXT_ONLY` (VPN, datacenter) ≤ ngay dưới `alert`: một mình loại IP không đủ để cảnh báo — tử số của LR (bao nhiêu phần
  tấn công đi qua datacenter) do nhóm chọn khi dựng họ tấn công, còn VPN công ty/đám mây là chuyện thường (họ `vpn_user`).

Đánh giá: "trước" = hành động THẬT pipeline đã ra lúc chạy MR24; "sau" = phát lại mọi lần thử qua đúng `combine_risk` với
trọng số và mức tối thiểu mới (luật đã khớp và xác suất hai mô hình ghi sẵn ở MR24 — không cần chạy lại pipeline).

    cd backend
    venv\\Scripts\\python.exe -m ml.corpus.calibrate_rules            # in bảng, ghi ml/artifacts/corpus/mr25_report.json
    venv\\Scripts\\python.exe -m ml.corpus.calibrate_rules --write    # và ghi trọng số mới vào hồ sơ hybrid đang dùng
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import random
from collections import defaultdict
from pathlib import Path

from app.detection.engine.registry import REGISTRY
from app.detection.engine.types import RuleHit
from app.detection.hybrid import ActionBands, HybridProfile, RuleWeightEntry, RuleWeights, combine_risk
from app.detection.hybrid.combine import REPUTATION_CATEGORY

CORPUS_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "corpus"
PROFILE_PATH = Path(__file__).resolve().parents[2] / "app" / "detection" / "hybrid" / "profiles" / "rba_calibrated.json"
# Tỉ lệ lần thử từ IP tấn công (trọng số dân số) ở val RBA, bỏ warm-up — ĐÚNG khung `hybrid_calibrate.calibrate_rule_weights` (MR11)
# đo độ chính xác. Bản đầu của MR25 ghi 0,0632 (sai khung dữ liệu); sửa ở MR26 — trọng số không bị trần đổi theo.
RBA_ATTACK_PRIOR = 0.0840
RBA_VALID = ("brute_force", "credential_stuffing", "password_spray_slow", "dormant_account_login", "rare_network_login")
CONTEXT_ONLY = ("datacenter_ip", "vpn_ip")
MR21_MIN_ACTIONS = {"brute_force": "alert", "credential_stuffing": "alert", "impossible_travel": "alert", "success_after_failures": "step_up", "blocklist_hit": "lock"}
MIN_HITS = 20  # dưới mức này không đủ để đo — giữ trọng số cũ (vd blocklist_hit: hành động do `min_action`, không do trọng số)
N_BOOT = 500
REPORT_PATH = CORPUS_DIR / "mr25_report.json"


def rule_hits(step: dict) -> list[RuleHit]:
    """Luật đã khớp của một lần thử như `combine_risk` nhận. Bản ghi MR24–MR26: `[luật, shadow]`; từ MR27: `[luật, shadow, forces]`."""
    return [
        RuleHit(h[0], "medium", "", {}, "shadow" if h[1] else "enforce", (), bool(h[2]) if len(h) > 2 else True)
        for h in step.get("hits", [])
    ]


def load(split: str) -> list[dict]:
    with (CORPUS_DIR / f"{split}.jsonl").open(encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def _counts(records: list[dict]) -> dict[str, list[int]]:
    """rule -> [khớp trên lần thử độc hại, số lần thử độc hại, khớp trên lần thử hợp lệ, số lần thử hợp lệ]."""
    n_mal = sum(s["malicious"] for r in records for s in r["steps"])
    n_ben = sum(not s["malicious"] for r in records for s in r["steps"])
    out = {rule: [0, n_mal, 0, n_ben] for rule in REGISTRY}
    for r in records:
        for s in r["steps"]:
            for rule in {h[0] for h in s.get("hits", [])}:
                out[rule][0 if s["malicious"] else 2] += 1
    return out


def posterior_weight(k_mal: int, n_mal: int, k_ben: int, n_ben: int, prior: float = RBA_ATTACK_PRIOR) -> float:
    lr = ((k_mal + 0.5) / (n_mal + 1)) / ((k_ben + 0.5) / (n_ben + 1))
    return prior * lr / (prior * lr + 1 - prior)


def caps(bands: ActionBands) -> tuple[float, float]:
    """(trần chung, trần `CONTEXT_ONLY`): trọng số lớn nhất mà MỘT MÌNH vẫn dưới `step_up` / dưới `alert` (điểm = round(p·100))."""
    return (bands.step_up_at - 1) / 100, (bands.alert_at - 1) / 100


def calibrate(records: list[dict], bands: ActionBands, *, n_boot: int = N_BOOT, seed: int = 0) -> dict[str, RuleWeightEntry]:
    """Trọng số mới cho các luật cần đo lại, đã chặn trần (`caps`); khoảng tin cậy là của SỐ ĐO, chưa chặn."""
    general_cap, context_cap = caps(bands)
    counts = _counts(records)
    by_kind = defaultdict(list)
    for r in records:
        by_kind[r["kind"]].append(r)
    rng = random.Random(seed)
    boot = defaultdict(list)
    for _ in range(n_boot):
        sample = [rng.choice(rows) for rows in by_kind.values() for _ in rows]
        for rule, (km, nm, kb, nb) in _counts(sample).items():
            boot[rule].append(posterior_weight(km, nm, kb, nb))
    entries = {}
    for rule, (km, nm, kb, nb) in counts.items():
        if rule in RBA_VALID or km + kb < MIN_HITS:
            continue
        samples = sorted(boot[rule])
        ci = (samples[int(0.025 * n_boot)], samples[int(0.975 * n_boot) - 1])
        weight, cap = posterior_weight(km, nm, kb, nb), context_cap if rule in CONTEXT_ONLY else general_cap
        entries[rule] = RuleWeightEntry(round(min(weight, cap), 4), True, km + kb, (round(ci[0], 4), round(ci[1], 4)),
                                        "corpus_mr24_capped" if weight > cap else "corpus_mr24")
    return entries


def registry_with(min_actions: dict[str, str | None]) -> dict:
    """Sổ đăng ký với mức tối thiểu ĐÚNG như `min_actions` (trọn bộ của một thời điểm, vd MR21): luật không có trong đó thì không có mức
    — để phát lại cấu hình cũ không lẫn mức thêm sau này (MR27 thêm `password_spray_slow`)."""
    return {rule: dataclasses.replace(spec, min_action=min_actions.get(rule)) for rule, spec in REGISTRY.items()}


def replay(records: list[dict], weights: RuleWeights, bands: ActionBands, *, with_models: bool = True, registry=None) -> list[list[str]]:
    """Hành động của từng lần thử khi gộp lại bằng `combine_risk` (cùng hàm của luồng thật) với `weights`. `with_models=False`:
    chỉ luật + danh tiếng (đo riêng phần báo nhầm do luật gây ra)."""
    out = []
    for r in records:
        actions = []
        for s in r["steps"]:
            hits = rule_hits(s)
            result = combine_risk(
                ml_probability=s.get("ml") if with_models else None, hits=hits, weights=weights, bands=bands,
                ml_geo_probability=s.get("ml_geo") if with_models else None, registry=registry,
            )
            actions.append(result.action)
        out.append(actions)
    return out


def metrics(records: list[dict], actions: list[list[str]]) -> dict:
    ben = [(r, a) for r, acts in zip(records, actions) for s, a in zip(r["steps"], acts) if not s["malicious"] and r["kind"] == "benign"]
    flagged = sum(a != "allow" for _, a in ben)
    friction = sum(a in ("step_up", "lock") for _, a in ben)
    by_family = defaultdict(lambda: [0, 0, 0])  # họ hợp lệ -> [bị cảnh báo trở lên, bị xác thực thêm/khoá, số lần thử]
    for r, a in ben:
        row = by_family[r["family"]]
        row[0] += a != "allow"
        row[1] += a in ("step_up", "lock")
        row[2] += 1
    families = {}
    for r, acts in zip(records, actions):
        fam = families.setdefault(r["family"], {"kind": r["kind"], "n": 0, "hit": 0})
        fam["n"] += 1
        relevant = [a for s, a in zip(r["steps"], acts) if (s["malicious"] if r["kind"] == "attack" else True)]
        fam["hit"] += any(a != "allow" for a in relevant)
    return {
        "legit_attempts": len(ben), "legit_alert_rate": round(flagged / len(ben), 4), "legit_step_up_or_lock_rate": round(friction / len(ben), 4),
        "legit_by_family": dict(sorted(by_family.items())),
        "families": {f: {"kind": v["kind"], "rate": round(v["hit"] / v["n"], 3)} for f, v in sorted(families.items())},
    }


def forced_on_legit(records: list[dict]) -> dict[str, dict]:
    """Mỗi luật có mức tối thiểu tạm thời của MR21: bao nhiêu lần thử HỢP LỆ bị chính luật đó ép hành động (bất kể mô hình) —
    số đo để chốt mức."""
    out = {rule: {"min_action_mr21": action, "legit_forced": 0, "families": defaultdict(int)} for rule, action in MR21_MIN_ACTIONS.items()}
    n_ben = 0
    for r in records:
        for s in r["steps"]:
            if s["malicious"]:
                continue
            n_ben += 1
            for hit in rule_hits(s):
                if hit.rule_id in out and not hit.is_shadow and hit.forces:
                    out[hit.rule_id]["legit_forced"] += 1
                    out[hit.rule_id]["families"][r["family"]] += 1
    return {rule: {**v, "legit_forced_rate": round(v["legit_forced"] / n_ben, 4), "families": dict(v["families"])} for rule, v in out.items()}


def replay_fidelity(records: list[dict], weights: RuleWeights, bands: ActionBands, registry) -> dict:
    """Phát lại với ĐÚNG cấu hình lúc chạy MR24 có ra lại hành động pipeline thật đã ghi không. Khác biệt duy nhất được phép:
    lần thử khớp ≥ 2 luật danh tiếng (MR25 đổi nhóm đó từ noisy-OR sang max)."""
    reputation = {rule for rule, spec in REGISTRY.items() if spec.category == REPUTATION_CATEGORY}
    n = same = explained = 0
    for r, acts in zip(records, replay(records, weights, bands, registry=registry)):
        for s, a in zip(r["steps"], acts):
            n += 1
            if a == s["action"]:
                same += 1
            elif sum(h[0] in reputation for h in s.get("hits", [])) >= 2:
                explained += 1
    return {"attempts": n, "identical": same, "differ_only_by_reputation_max": explained, "unexplained": n - same - explained}


def _weights_before(profile: HybridProfile) -> RuleWeights:
    """"Trước" = trọng số RBA của MR11. Hồ sơ đã được ghi bởi `--write` thì lấy lại từ báo cáo lần trước (chạy lại cho cùng số)."""
    if not any((e.source or "").startswith("corpus_mr24") for e in profile.weights.entries.values()):
        return profile.weights
    return RuleWeights.from_dict(json.loads(REPORT_PATH.read_text(encoding="utf-8"))["weights_before"])


def with_sources(weights: RuleWeights) -> RuleWeights:
    """Mọi trọng số ghi nguồn: "rba" (đo trên RBA ở MR11), "default" (chưa đo được, giá trị đặt trước), "corpus_mr24*" (MR25)."""
    return RuleWeights(
        {rule: e if e.source else dataclasses.replace(e, source="rba" if e.calibrated else "default") for rule, e in weights.entries.items()},
        weights.default_weight,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="ghi trọng số mới vào hồ sơ hybrid đang dùng")
    args = parser.parse_args()

    profile = HybridProfile.from_file(PROFILE_PATH)
    before_weights = _weights_before(profile)
    calibration, evaluation = load("calibration"), load("evaluation")
    new_entries = calibrate(calibration, profile.bands)
    weights_after = RuleWeights({**before_weights.entries, **new_entries}, before_weights.default_weight)

    report = {"prior": RBA_ATTACK_PRIOR, "caps": caps(profile.bands), "measured": {
        rule: round(posterior_weight(*c), 4) for rule, c in _counts(calibration).items() if rule in new_entries}, "weights_before": before_weights.to_dict(), "rules": {}, "evaluation": {}}
    counts_eval = _counts(evaluation)
    for rule in REGISTRY:
        before, after = before_weights.entries.get(rule), weights_after.entries.get(rule)
        km, nm, kb, nb = counts_eval[rule]
        report["rules"][rule] = {
            "before": None if before is None else before.to_dict(), "after": None if after is None else after.to_dict(),
            "eval_fires_on_malicious": km, "eval_fires_on_legit": kb,
        }
    recorded = [[s["action"] for s in r["steps"]] for r in evaluation]  # hành động thật của pipeline lúc chạy MR24
    before_registry = registry_with(MR21_MIN_ACTIONS)
    report["replay_fidelity"] = replay_fidelity(evaluation, before_weights, profile.bands, before_registry)
    report["evaluation"]["before"] = {
        "all_sources": metrics(evaluation, recorded),
        "rules_only": metrics(evaluation, replay(evaluation, before_weights, profile.bands, with_models=False, registry=before_registry)),
    }
    report["evaluation"]["after"] = {
        "all_sources": metrics(evaluation, replay(evaluation, weights_after, profile.bands)),
        "rules_only": metrics(evaluation, replay(evaluation, weights_after, profile.bands, with_models=False)),
    }
    report["min_action_on_legit"] = {"calibration": forced_on_legit(calibration), "evaluation": forced_on_legit(evaluation)}
    REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"{'luật':28s} {'trước':>14s} {'sau':>24s}   khớp trên bộ đánh giá: độc hại / hợp lệ")
    for rule, row in report["rules"].items():
        b = row["before"]["weight"] if row["before"] else None
        a = row["after"]
        after_txt = f"{a['weight']:.3f} [{a['ci95'][0]:.3f}-{a['ci95'][1]:.3f}] {a.get('source') or 'rba'}" if a and a.get("ci95") else (f"{a['weight']:.3f}" if a else "-")
        print(f"{rule:28s} {('%.3f' % b) if b is not None else '-':>14s} {after_txt:>24s}   {row['eval_fires_on_malicious']} / {row['eval_fires_on_legit']}")
    f = report["replay_fidelity"]
    print(f"phát lại cấu hình MR24: {f['identical']}/{f['attempts']} lần thử ra đúng hành động thật, {f['differ_only_by_reputation_max']} khác do gộp danh tiếng bằng max, {f['unexplained']} không giải thích được")
    for label in ("before", "after"):
        e = report["evaluation"][label]
        print(f"[{label}] hợp lệ bị cảnh báo: mọi nguồn {e['all_sources']['legit_alert_rate']:.1%} | chỉ luật {e['rules_only']['legit_alert_rate']:.1%}"
              f"  (OTP/khoá: {e['all_sources']['legit_step_up_or_lock_rate']:.1%} | {e['rules_only']['legit_step_up_or_lock_rate']:.1%})")
    if args.write:
        updated = dataclasses.replace(profile, weights=with_sources(weights_after))  # giữ nguyên ngưỡng, hiệu chỉnh ML, độ lệch miền
        PROFILE_PATH.write_text(json.dumps(updated.to_dict(), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"đã ghi {len(new_entries)} trọng số vào {PROFILE_PATH}")


if __name__ == "__main__":
    main()
