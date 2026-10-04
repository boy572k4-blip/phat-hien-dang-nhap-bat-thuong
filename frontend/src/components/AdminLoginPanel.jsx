import { useEffect, useState } from "react";

import { apiClient } from "../services/api";
import "./BlocklistPanel.css";

const LIMIT = 20;
const OUTCOME_LABELS = { success: "✅ Thành công", failed: "❌ Sai mật khẩu", rejected: "⛔ Bị từ chối" };
const SCOPE_LABELS = { ip: "quá nhiều lần sai từ IP này", account: "quá nhiều lần sai vào tài khoản này" };

// MR32 — nhật ký đăng nhập quản trị (GET /admin/login-attempts, đọc từ audit_log): chính cửa vào hệ thống giám sát cũng được
// giám sát. "IP quen" = IP đã từng đăng nhập quản trị thành công bằng tên đó — lần sai từ IP lạ và IP quen được đếm riêng.
export default function AdminLoginPanel() {
  const [attempts, setAttempts] = useState(null);
  const [error, setError] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get("/admin/login-attempts", { params: { limit: LIMIT } })
      .then((res) => {
        if (!cancelled) setAttempts(res.data);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được nhật ký đăng nhập quản trị.");
      });
    return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  return (
    <section className="dashboard-panel blocklist-panel" aria-label="Đăng nhập quản trị gần đây">
      <h2>
        Đăng nhập quản trị gần đây (MR32)
        <button type="button" className="blocklist-panel__refresh" onClick={() => setReloadKey((k) => k + 1)} title="Làm mới">
          🔄
        </button>
      </h2>
      <div className="dashboard-panel__body">
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && attempts === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {!error && attempts !== null && attempts.length === 0 && (
          <p className="dashboard-panel__placeholder">Chưa có lần đăng nhập quản trị nào được ghi.</p>
        )}
        {!error && attempts !== null && attempts.length > 0 && (
          <table className="blocklist-panel__table">
            <thead>
              <tr>
                <th>Thời điểm</th>
                <th>Kết quả</th>
                <th>Tên đăng nhập</th>
                <th>IP</th>
                <th>Trình duyệt</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.created_at).toLocaleString("vi-VN")}</td>
                  <td title={a.refused_scope ? SCOPE_LABELS[a.refused_scope] : ""}>
                    {OUTCOME_LABELS[a.outcome] ?? a.outcome}
                  </td>
                  <td className="blocklist-panel__value">{a.username}</td>
                  <td className="blocklist-panel__value">
                    {a.ip} <span className="blocklist-panel__added-by">({a.familiar_ip ? "IP quen" : "IP lạ"})</span>
                  </td>
                  <td className="blocklist-panel__reason" title={a.user_agent ?? ""}>
                    {a.user_agent ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
