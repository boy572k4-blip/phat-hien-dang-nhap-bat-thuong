"""mr23_one_incident_one_score

MR23 — một sự cố = một cảnh báo, một điểm rủi ro:
  - `alerts.alert_type` bị xoá: chỉ còn một loại cảnh báo (sự cố của hybrid risk engine). Cảnh báo cũ giữ loại gốc trong
    `explanation.legacy_alert_type`; cảnh báo cũ của luật tầng 1 (brute_force, credential_stuffing, impossible_travel) chưa
    có `rule_id` thì nhận luôn mã luật cùng tên (luật v2 thay thế, docs/rule-unification.md).
  - Chỉ mục tra sự cố đang mở: (user_id, status, last_seen_at) thay cho (user_id, attack_family, status) — từ MR23 họ tấn
    công không còn nằm trong khoá gộp.
  - `login_events.risk_score` (điểm cộng tay của tầng 2, Tuần 4; từ MR21 chỉ là bản sao điểm hybrid) và
    `login_events.ml_anomaly_score` (tầng 3, Tuần 7; từ MR22 là nguồn `ml_geo` bên trong điểm hybrid) bị xoá — điểm duy nhất
    là `hybrid_risk_score`.

Downgrade tạo lại các cột: `alert_type` lấy lại từ `legacy_alert_type` (cảnh báo mới thành `hybrid_risk`), `risk_score`
chép lại từ `hybrid_risk_score` (đúng với mọi lần thử từ MR21); điểm tầng 2 cũ hơn MR21 và `ml_anomaly_score` KHÔNG khôi
phục được — sao lưu DB trước khi nâng cấp nếu cần giữ.

Revision ID: 7d2c1e5a9b30
Revises: 832bb849e97d
Create Date: 2026-10-03 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7d2c1e5a9b30'
down_revision: Union[str, None] = '832bb849e97d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RULE_TYPES = ("brute_force", "credential_stuffing", "impossible_travel")  # loại cảnh báo tầng 1 = mã luật v2 cùng tên

_alerts = sa.table(
    "alerts",
    sa.column("id", sa.Integer),
    sa.column("alert_type", sa.String),
    sa.column("rule_id", sa.String),
    sa.column("explanation", sa.JSON),
)


def upgrade() -> None:
    bind = op.get_bind()
    legacy = bind.execute(
        sa.select(_alerts.c.id, _alerts.c.alert_type, _alerts.c.rule_id, _alerts.c.explanation).where(_alerts.c.alert_type != "hybrid_risk")
    ).all()
    for row in legacy:
        values = {"explanation": {**(row.explanation or {}), "legacy_alert_type": row.alert_type}}
        if row.rule_id is None and row.alert_type in _RULE_TYPES:
            values["rule_id"] = row.alert_type
        bind.execute(_alerts.update().where(_alerts.c.id == row.id).values(**values))

    op.drop_index("ix_alerts_dedup_lookup", table_name="alerts")
    op.create_index("ix_alerts_open_incident", "alerts", ["user_id", "status", "last_seen_at"], unique=False)
    op.drop_column("alerts", "alert_type")
    op.drop_column("login_events", "risk_score")
    op.drop_column("login_events", "ml_anomaly_score")


def downgrade() -> None:
    op.add_column("login_events", sa.Column("ml_anomaly_score", sa.Float(), nullable=True))
    op.add_column("login_events", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.execute("UPDATE login_events SET risk_score = hybrid_risk_score")

    op.add_column("alerts", sa.Column("alert_type", sa.String(length=32), nullable=True))
    bind = op.get_bind()
    rows = bind.execute(sa.select(_alerts.c.id, _alerts.c.rule_id, _alerts.c.explanation)).all()
    for row in rows:
        explanation = dict(row.explanation or {})
        legacy_type = explanation.pop("legacy_alert_type", None)
        values = {"alert_type": legacy_type or "hybrid_risk"}
        if legacy_type is not None:
            # sa.null(): cột JSON nhận None của Python thành JSON `null`, không phải NULL của SQL như trước khi nâng cấp.
            values["explanation"] = explanation if explanation else sa.null()
            if legacy_type in _RULE_TYPES and row.rule_id == legacy_type:
                values["rule_id"] = None
        bind.execute(_alerts.update().where(_alerts.c.id == row.id).values(**values))
    op.alter_column("alerts", "alert_type", existing_type=sa.String(length=32), nullable=False)
    op.drop_index("ix_alerts_open_incident", table_name="alerts")
    op.create_index("ix_alerts_dedup_lookup", "alerts", ["user_id", "attack_family", "status"], unique=False)
