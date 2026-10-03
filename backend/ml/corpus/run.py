"""Chạy bộ dữ liệu hiệu chỉnh (MR24) qua CHÍNH pipeline thật và ghi bằng chứng thô từng lần thử.

Mỗi biến thể: DB SQLite trong bộ nhớ MỚI + fakeredis MỚI (không đụng Postgres/Redis dev), lịch sử ghi thẳng KÈM sổ sách như
một lần đăng nhập thành công thật (baseline giờ, thiết bị/vị trí quen — bài học MR22), rồi từng lần thử đi qua
`pipeline._run_detection_pipeline_sync`. Mô hình và tình báo nạp MỘT lần mỗi tiến trình con.

Mỗi lần thử ghi: hành động, điểm, luật đã khớp (kèm shadow), xác suất `hybrid_cp2` và `ml_geo`, luật đã ép hành động — đủ để
MR25/MR26 tính lại điểm với trọng số/ngưỡng khác mà không chạy lại pipeline. `--with-model-inputs` (MR26) ghi thêm điểm THÔ của
`hybrid_cp2` (trước ánh xạ điểm -> xác suất), xác suất đuôi từng thành phần và 50 đặc trưng.

    cd backend
    venv\\Scripts\\python.exe -m ml.corpus.run --split both --workers 6
    venv\\Scripts\\python.exe -m ml.corpus.run --split both --with-model-inputs --out-dir ml/artifacts/corpus/mr26
Kết quả: ml/artifacts/corpus/{calibration,evaluation}.jsonl + summary.json (không commit — tái tạo được từ seed). Hành động ghi
lại là của cấu hình lúc chạy: số "trước" của MR25 dựa trên lần chạy với cấu hình MR24, nên lần chạy sau ghi ra thư mục khác."""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import statistics
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parents[1] / "artifacts" / "corpus"
BASE_TS = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)  # 00:00 UTC của "ngày đo"

_capture: list = []
_pools = None


def _model_inputs(engine, features) -> dict:
    """Điểm thô `hybrid_cp2` (−log10 xác suất đuôi nhỏ nhất), xác suất đuôi từng thành phần, đặc trưng (NaN -> None)."""
    import math

    import pandas as pd

    if features is None or engine.scorer is None:
        return {"ml_raw": None, "ml_tails": None, "features": None}
    frame = pd.DataFrame([features])
    tails = engine.scorer._tails(frame)[0]
    return {
        "ml_raw": round(float(-math.log10(max(min(tails), 1e-300))), 5),
        "ml_tails": {c.name: round(float(t), 6) for c, t in zip(engine.scorer.components, tails)},
        "features": {k: (None if v is None or (isinstance(v, float) and math.isnan(v)) else round(float(v), 5)) for k, v in features.items()},
    }


def _init_worker(with_model_inputs: bool = False) -> None:
    """Một lần mỗi tiến trình: nạp mô hình hybrid, tình báo, kho IP; bọc HybridEngine.evaluate để ghi bằng chứng."""
    global _pools
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import models  # noqa: F401
    from app.database import Base
    from app.detection import hybrid_runtime, model_registry
    from app.detection.rule_engine_runtime import load_threat_intel_at_startup
    from ml.corpus.ip_pools import build_pools

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    model_registry.ensure_registered(db)
    hybrid_runtime._engine = None  # engine riêng của tiến trình này — không mang theo thuộc tính gắn lên singleton ở nơi khác
    hybrid_runtime.load_at_startup(db)
    db.close()
    if not hybrid_runtime.get_engine().ml_available:
        raise RuntimeError("Không nạp được mô hình hybrid_cp2 — bộ dữ liệu cần mô hình thật (chạy ml.rba.* trước)")
    load_threat_intel_at_startup()
    _pools = build_pools()

    original = hybrid_runtime.HybridEngine.evaluate

    def capturing(self, features, hits, **kwargs):
        hits = list(hits)
        result = original(self, features, hits, **kwargs)
        _capture.append({
            "ml": None if result.ml_probability is None else round(result.ml_probability, 5),
            "ml_geo": None if result.ml_geo_probability is None else round(result.ml_geo_probability, 5),
            "hits": [[h.rule_id, bool(h.is_shadow), bool(h.forces)] for h in hits],  # forces: MR27 (phạm vi ASN không ép)
            "forced_by": result.overridden_by,
            **(_model_inputs(self, features) if with_model_inputs else {}),
        })
        return result

    hybrid_runtime.HybridEngine.evaluate = capturing


def _run_variant(args: tuple[str, int]) -> dict:
    family, seed = args
    import fakeredis
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.detection.pipeline as pipeline
    import app.detection.rate_counter as rate_counter
    from app.database import Base
    from app.detection.baseline import record_known_device_if_new, record_known_location_if_new, update_baseline_after_successful_login
    from app.detection.login_context import invalidate_global_counts
    from app.detection.rule_engine_runtime import invalidate_blocklist_cache, invalidate_rule_config_cache
    from app.models import Alert, LoginEvent, User
    from app.utils.device import compute_device_fingerprint
    from ml.corpus.families import build_variant

    variant = build_variant(family, seed, _pools)
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    pipeline.SessionLocal = factory
    rate_counter.redis_client = fakeredis.FakeRedis(decode_responses=True)
    invalidate_blocklist_cache()
    invalidate_rule_config_cache()
    invalidate_global_counts()

    db = factory()
    users = {}
    for name in variant.accounts:
        user = User(username=name, password_hash="x")
        db.add(user)
        db.flush()
        users[name] = user
    for h in variant.history:  # ghi như một lần đăng nhập thành công thật, kèm sổ sách
        user = users[h.username]
        event = LoginEvent(
            user_id=user.id, attempted_username=h.username, success=True, ip_address=h.ip.ip, user_agent=h.user_agent,
            device_fingerprint=compute_device_fingerprint(h.user_agent), country=h.ip.country, city=h.ip.city,
            latitude=h.ip.latitude, longitude=h.ip.longitude, asn=h.ip.asn, is_synthetic=True,
            created_at=BASE_TS + timedelta(seconds=h.offset_s),
        )
        db.add(event)
        db.flush()
        update_baseline_after_successful_login(db, user, event)
        record_known_device_if_new(db, user, event.device_fingerprint, h.user_agent)
        record_known_location_if_new(db, user, event.country, event.city)
    db.commit()
    user_ids = {name: u.id for name, u in users.items()}
    db.close()

    steps = []
    for i, s in enumerate(variant.steps):
        _capture.clear()
        result = pipeline._run_detection_pipeline_sync(
            username=s.username, user_id=user_ids.get(s.username), success=s.success, ip=s.ip.ip, user_agent=s.user_agent,
            timestamp=BASE_TS + timedelta(seconds=s.offset_s),
        )
        evidence = _capture[-1] if _capture else {}
        steps.append({
            "i": i, "username": s.username, "known_account": s.username in user_ids, "success": s.success,
            "ip": s.ip.ip, "pool": s.ip.pool, "country": s.ip.country, "asn": s.ip.asn, "ua": s.user_agent[:60],
            "offset_s": round(s.offset_s, 1), "malicious": s.malicious,
            "action": result.hybrid_action, "score": result.hybrid_risk_score, **evidence,
        })
    db = factory()
    alerts = db.query(Alert).count()
    events = db.query(LoginEvent).filter(LoginEvent.is_synthetic.is_(False)).count()
    db.close()
    engine.dispose()
    return {"id": variant.id, "family": family, "kind": variant.kind, "seed": seed, "accounts": len(variant.accounts),
            "history": len(variant.history), "events": events, "alerts": alerts, "steps": steps}


def summarize(records: list[dict]) -> dict:
    """Số đo theo họ: tấn công -> tỉ lệ biến thể bị phát hiện (ít nhất một lần thử của kẻ tấn công khác `allow`), bị chặn
    mạnh (step_up/lock), bước phát hiện đầu tiên; hợp lệ -> tỉ lệ lần thử / biến thể bị báo nhầm, bị đòi OTP hay khoá."""
    by_family = defaultdict(list)
    for r in records:
        by_family[r["family"]].append(r)
    out = {}
    for family, rows in sorted(by_family.items()):
        kind = rows[0]["kind"]
        if kind == "attack":
            detected, strong, first = 0, 0, []
            for r in rows:
                mal = [s for s in r["steps"] if s["malicious"]]
                hit = [k for k, s in enumerate(mal) if s["action"] not in (None, "allow")]
                detected += bool(hit)
                strong += any(s["action"] in ("step_up", "lock") for s in mal)
                if hit:
                    first.append(hit[0] + 1)
            out[family] = {"kind": kind, "variants": len(rows), "detected": round(detected / len(rows), 3),
                           "step_up_or_lock": round(strong / len(rows), 3),
                           "median_first_detected_step": statistics.median(first) if first else None,
                           "alerts_per_variant": round(statistics.mean(r["alerts"] for r in rows), 2)}
        else:
            attempts = [s for r in rows for s in r["steps"]]
            flagged = [s for s in attempts if s["action"] not in (None, "allow")]
            out[family] = {"kind": kind, "variants": len(rows), "attempts": len(attempts),
                           "attempt_alert_rate": round(len(flagged) / len(attempts), 3),
                           "attempt_step_up_or_lock_rate": round(sum(s["action"] in ("step_up", "lock") for s in attempts) / len(attempts), 3),
                           "variants_with_any_alert": round(sum(any(s["action"] not in (None, "allow") for s in r["steps"]) for r in rows) / len(rows), 3)}
    return out


def main() -> None:
    from ml.corpus.families import FAMILIES, SPLIT_SEEDS, VARIANTS_PER_FAMILY

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("calibration", "evaluation", "both"), default="both")
    parser.add_argument("--per-family", type=int, default=VARIANTS_PER_FAMILY)
    parser.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 2))
    parser.add_argument("--families", nargs="*", default=None)
    parser.add_argument("--with-model-inputs", action="store_true", help="ghi thêm điểm thô, xác suất đuôi, đặc trưng của hybrid_cp2 (MR26)")
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    families = tuple(args.families) if args.families else tuple(FAMILIES)
    splits = ("calibration", "evaluation") if args.split == "both" else (args.split,)
    summary = {}
    for split in splits:
        jobs = [(family, SPLIT_SEEDS[split][i]) for family in families for i in range(args.per_family)]
        started = time.perf_counter()
        with mp.get_context("spawn").Pool(args.workers, initializer=_init_worker, initargs=(args.with_model_inputs,)) as pool:
            records = pool.map(_run_variant, jobs, chunksize=4)
        with (out_dir / f"{split}.jsonl").open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        summary[split] = {"variants": len(records), "attempts": sum(len(r["steps"]) for r in records),
                          "seconds": round(time.perf_counter() - started, 1), "families": summarize(records)}
        print(f"{split}: {len(records)} biến thể, {summary[split]['attempts']} lần thử, {summary[split]['seconds']} s")
    summary["generated_at"] = datetime.now(timezone.utc).isoformat()
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({s: summary[s]["families"] for s in splits}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
