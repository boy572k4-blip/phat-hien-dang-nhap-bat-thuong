import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./ModelHealthPage.css";

function verdictClass(verdict) {
  if (verdict === "trôi đáng kể") return "model-health__verdict--bad";
  if (verdict === "trôi vừa") return "model-health__verdict--warn";
  if (verdict === "ổn định") return "model-health__verdict--good";
  return "";
}

const fmtDate = (value) => (value ? new Date(value).toLocaleString("vi-VN") : "—");
const fmtNum = (value, digits = 2) => (value === null || value === undefined ? "—" : value.toFixed(digits));
const fmtPct = (value) => (value === null || value === undefined ? "—" : `${(value * 100).toFixed(1)}%`);

// Bảng khoảng cách RBA → hệ thống dùng cùng ngưỡng PSI nhưng KHÔNG gọi là "trôi" (hai nguồn khác nhau, không phải thay đổi theo thời gian).
const GAP_LABELS = { "ổn định": "gần", "trôi vừa": "khác vừa", "trôi đáng kể": "khác xa" };

function FeatureTable({ rows, gap = false }) {
  return (
    <table className="model-health-table">
      <thead>
        <tr>
          <th>Đặc trưng</th>
          <th>PSI</th>
          <th>{gap ? "Mức khác biệt" : "Kết luận"}</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f) => (
          <tr key={f.feature}>
            <td className="model-health-table__mono">{f.feature}</td>
            <td>{f.psi === null ? "—" : f.psi.toFixed(3)}</td>
            <td className={gap ? "" : verdictClass(f.verdict)}>{gap ? GAP_LABELS[f.verdict] ?? f.verdict : f.verdict}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// MR17 "Dashboard v2" — phiên bản mô hình + trôi dữ liệu. MR26: "trôi" là cửa sổ đầu so với cửa sổ gần nhất của CHÍNH hệ
// thống (cùng nguồn — đọc được); khoảng cách RBA → hệ thống tách riêng, kèm độ lệch miền đang dùng và ước lượng từ log thật.
export default function ModelHealthPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  function load(refresh = false) {
    if (refresh) setRefreshing(true);
    apiClient
      .get("/model-health", { params: refresh ? { refresh: true } : {} })
      .then((res) => setData(res.data))
      .catch(() => setError("Không tải được sức khoẻ mô hình (cần đăng nhập quản trị)."))
      .finally(() => setRefreshing(false));
  }

  useEffect(() => load(false), []);

  const score = data?.score_drift;
  const shift = data?.domain_shift;

  return (
    <main className="model-health-page">
      <h1>🩺 Sức khoẻ mô hình</h1>

      {error && <p className="model-health-page__placeholder">{error}</p>}
      {!error && data === null && (
        <p className="model-health-page__placeholder">
          <span className="spinner" />
          Đang tải (lần đầu có thể mất vài giây — tính lại đặc trưng của hai cửa sổ log thật)...
        </p>
      )}

      {data && (
        <>
          <section className="model-health-panel">
            <h2>Phiên bản đã đăng ký</h2>
            {data.versions.length === 0 ? (
              <p className="model-health-page__placeholder">Chưa có phiên bản nào được đăng ký.</p>
            ) : (
              <table className="model-health-table">
                <thead>
                  <tr>
                    <th>Tên</th>
                    <th>Phiên bản</th>
                    <th>Đang dùng</th>
                    <th>Huấn luyện lúc</th>
                    <th>Chữ ký đặc trưng</th>
                  </tr>
                </thead>
                <tbody>
                  {data.versions.map((v) => (
                    <tr key={v.id}>
                      <td>{v.name}</td>
                      <td>{v.version}</td>
                      <td>{v.is_active ? "✅ Đang dùng" : "—"}</td>
                      <td>{fmtDate(v.trained_at)}</td>
                      <td className="model-health-table__mono">{v.feature_signature ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="model-health-panel">
            <div className="model-health-panel__header">
              <h2>Trôi dữ liệu của hệ thống (cửa sổ đầu → gần nhất)</h2>
              <button type="button" disabled={refreshing} onClick={() => load(true)}>
                {refreshing ? "Đang tính..." : "🔄 Tính lại"}
              </button>
            </div>
            <p className="model-health-page__hint">
              Tính lúc {fmtDate(data.drift_computed_at)}. Cửa sổ đầu: {data.drift_n_reference.toLocaleString("vi-VN")} lần thử (
              {fmtDate(data.drift_reference_from)} → {fmtDate(data.drift_reference_to)}); gần nhất: {data.drift_n_current.toLocaleString("vi-VN")} lần
              thử ({fmtDate(data.drift_current_from)} → {fmtDate(data.drift_current_to)}). Cùng nguồn, cùng cách tính — PSI lớn nghĩa là lưu lượng
              đang thay đổi (người dùng/mạng mới, đợt tấn công, chạy demo).
              {data.drift_low_confidence && (
                <strong className="model-health-page__warning"> ⚠️ Mỗi cửa sổ cần ít nhất 30 lần thử — số dưới đây chỉ mang tính minh hoạ.</strong>
              )}
            </p>
            {score && (
              <table className="model-health-table">
                <tbody>
                  <tr>
                    <td>PSI của điểm mô hình hybrid_cp2</td>
                    <td>{fmtNum(score.psi, 3)}</td>
                    <td className={verdictClass(score.verdict)}>{score.verdict}</td>
                  </tr>
                  <tr>
                    <td>Lần thử mà riêng mô hình đủ cảnh báo</td>
                    <td colSpan={2}>
                      {fmtPct(score.ml_alert_share_reference)} (cửa sổ đầu) → {fmtPct(score.ml_alert_share_current)} (gần nhất)
                    </td>
                  </tr>
                </tbody>
              </table>
            )}
            <FeatureTable rows={data.drift_top_features} />
          </section>

          <section className="model-health-panel">
            <h2>Khoảng cách dữ liệu huấn luyện RBA → hệ thống</h2>
            <p className="model-health-page__hint">
              Không phải "trôi": RBA là dữ liệu khác quốc gia, nhà mạng và quy mô (các đặc trưng độ hiếm tính theo số lượt của chính hệ thống), nên
              khoảng cách này luôn lớn. Vì vậy điểm thô của mô hình được trừ một độ lệch miền trước khi đổi ra xác suất — mô hình không train lại.
            </p>
            {shift && (
              <table className="model-health-table">
                <tbody>
                  <tr>
                    <td>Độ lệch miền đang dùng (đăng nhập thành công)</td>
                    <td colSpan={2}>
                      {fmtNum(shift.success)}
                      {shift.ci95_success && ` (KTC 95% ${fmtNum(shift.ci95_success[0])}–${fmtNum(shift.ci95_success[1])})`} — đo trên{" "}
                      {shift.source === "corpus_mr24" ? "bộ kịch bản tấn công có nhãn" : shift.source ?? "—"}
                    </td>
                  </tr>
                  <tr>
                    <td>Ước lượng lại từ log thật (trung vị lần thành công)</td>
                    <td colSpan={2}>
                      {shift.live_estimate === null ? `chưa đủ dữ liệu (${shift.live_n} lần thành công, cần 30)` : `${fmtNum(shift.live_estimate)} (${shift.live_n} lần thành công)`}
                    </td>
                  </tr>
                </tbody>
              </table>
            )}
            <p className="model-health-page__hint">
              Tham chiếu {data.rba_gap_n_reference.toLocaleString("vi-VN")} dòng train RBA, so với cửa sổ gần nhất.
            </p>
            <FeatureTable rows={data.rba_gap_top_features} gap />
          </section>
        </>
      )}
    </main>
  );
}
