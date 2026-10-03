import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { apiClient } from "../services/api";

// Khu vực biểu đồ điểm rủi ro theo thời gian (nhiệm vụ 4.3) — nối dữ liệu
// thật từ GET /login-events (lấy 100 bản ghi gần nhất, vẽ theo thời gian).
// `refreshKey` tăng lên khi có cảnh báo mới qua WebSocket (nhiệm vụ 5.3).
// MR23: vẽ điểm DUY NHẤT của mỗi lần thử (hybrid risk engine) — trước đó biểu đồ vẽ điểm cộng tay của tầng 2 trong khi
// cảnh báo dùng điểm hybrid — và kẻ đúng ngưỡng hành động đang dùng (`action_bands` của API) thay vì 40/70 cố định.
const BAND_LINES = [
  { key: "alert_at", label: "cảnh báo", color: "#e0a800" },
  { key: "step_up_at", label: "xác thực thêm", color: "#e8590c" },
  { key: "lock_at", label: "khoá", color: "#d9363e" },
];

export default function RiskChartPanel({ refreshKey = 0 }) {
  const [points, setPoints] = useState(null);
  const [bands, setBands] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    apiClient
      .get("/login-events", { params: { page: 1, page_size: 100 } })
      .then((res) => {
        if (cancelled) return;
        const items = [...res.data.items].reverse(); // đảo lại thành thứ tự thời gian tăng dần
        setBands(res.data.action_bands);
        setPoints(
          items.map((event) => ({
            time: new Date(event.created_at).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" }),
            score: event.hybrid_risk_score, // null: lần thử cũ hơn MR12 hoặc khối chấm điểm lỗi — để trống, không vẽ thành 0
          }))
        );
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được dữ liệu biểu đồ.");
      });

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <section className="dashboard-panel" aria-label="Biểu đồ điểm rủi ro">
      <h2>Biểu đồ điểm rủi ro</h2>
      <div className="dashboard-panel__body">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && points === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {!error && points !== null && points.length === 0 && (
          <p className="dashboard-panel__placeholder">Chưa có dữ liệu đăng nhập.</p>
        )}
        {!error && points !== null && points.length > 0 && (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={points} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={20} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} />
              <Tooltip formatter={(value) => [value, "điểm"]} />
              {bands &&
                BAND_LINES.map(({ key, label, color }) => (
                  <ReferenceLine
                    key={key}
                    y={bands[key]}
                    stroke={color}
                    strokeDasharray="4 4"
                    label={{ value: `${label} ${bands[key]}`, position: "insideTopRight", fontSize: 9, fill: color }}
                  />
                ))}
              <Line type="monotone" dataKey="score" stroke="#4C72B0" dot={false} strokeWidth={2} connectNulls={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>
    </section>
  );
}
