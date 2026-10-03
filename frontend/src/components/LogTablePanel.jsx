import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { apiClient } from "../services/api";
import { ACTION_LABELS, actionLabel, actionLevel } from "../services/risk";
import "./LogTablePanel.css";

const PAGE_SIZE = 15;

const EMPTY_FILTERS = { username: "", success: "", action: "", is_synthetic: "" };

// MR23: tô màu dòng theo HÀNH ĐỘNG đã quyết định cho lần thử (đã gồm ngưỡng riêng của tài khoản và hành động tối thiểu
// của luật), không theo ngưỡng điểm cứng 40/70 của Tuần 4.
function rowClassName(action) {
  const level = actionLevel(action);
  return level ? `risk-row--${level}` : "";
}

// Chuyển filter UI (chuỗi rỗng = "tất cả") thành query param gửi backend.
function buildParams(page, filters) {
  const params = { page, page_size: PAGE_SIZE };
  if (filters.username.trim()) params.username = filters.username.trim();
  if (filters.success !== "") params.success = filters.success === "true";
  if (filters.action !== "") params.action = filters.action;
  if (filters.is_synthetic !== "") params.is_synthetic = filters.is_synthetic === "true";
  return params;
}

// Khu vực bảng log đăng nhập (nhiệm vụ 4.3) — nối GET /login-events thật,
// có phân trang + BỘ LỌC (nâng cấp sau Tuần 7: log lên tới hàng nghìn dòng,
// cần lọc theo username/kết quả/hành động/dữ liệu thật-hay-giả-lập).
// `refreshKey` tăng lên mỗi khi có cảnh báo mới qua WebSocket (nhiệm vụ
// 5.3) để bảng tự làm mới mà không cần reload trang.
export default function LogTablePanel({ refreshKey = 0 }) {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [usernameInput, setUsernameInput] = useState(""); // gõ ngay, chỉ áp filter sau 1 nhịp nghỉ
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Debounce ô tìm username 350ms — tránh gọi API dồn dập mỗi ký tự gõ.
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters((prev) => (prev.username === usernameInput ? prev : { ...prev, username: usernameInput }));
      setPage(1);
    }, 350);
    return () => clearTimeout(timer);
  }, [usernameInput]);

  useEffect(() => {
    let cancelled = false;
    // Chỉ hiện spinner toàn khung khi CHƯA có dữ liệu gì (lần đầu). Khi
    // refetch ngầm do có alert mới (refreshKey đổi) hoặc đổi bộ lọc, giữ
    // nguyên bảng cũ trên màn hình cho tới khi có dữ liệu mới — tránh giật
    // hình lúc demo.
    if (data === null) setLoading(true);
    setError(null);

    apiClient
      .get("/login-events", { params: buildParams(page, filters) })
      .then((res) => {
        if (!cancelled) setData(res.data);
      })
      .catch(() => {
        if (!cancelled) setError("Không tải được log đăng nhập.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [page, refreshKey, filters]);

  function updateFilter(key, value) {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setPage(1); // đổi bộ lọc thì quay lại trang 1
  }

  const hasActiveFilters = usernameInput !== "" || Object.values(filters).some((v) => v !== "");
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  return (
    <section className="dashboard-panel" aria-label="Bảng log đăng nhập">
      <h2>Log đăng nhập</h2>

      <div className="log-table__filters">
        <input
          type="text"
          placeholder="Tìm username..."
          value={usernameInput}
          onChange={(e) => setUsernameInput(e.target.value)}
        />
        <select value={filters.success} onChange={(e) => updateFilter("success", e.target.value)}>
          <option value="">Kết quả: tất cả</option>
          <option value="true">Thành công</option>
          <option value="false">Thất bại</option>
        </select>
        <select value={filters.action} onChange={(e) => updateFilter("action", e.target.value)}>
          <option value="">Hành động: tất cả</option>
          {Object.entries(ACTION_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        <select value={filters.is_synthetic} onChange={(e) => updateFilter("is_synthetic", e.target.value)}>
          <option value="">Dữ liệu: tất cả</option>
          <option value="false">Chỉ dữ liệu thật</option>
          <option value="true">Chỉ dữ liệu giả lập</option>
        </select>
        {hasActiveFilters && (
          <button
            type="button"
            className="log-table__clear-filters"
            onClick={() => {
              setFilters(EMPTY_FILTERS);
              setUsernameInput("");
              setPage(1);
            }}
          >
            Xoá lọc
          </button>
        )}
      </div>

      <div className="dashboard-panel__body log-table">
        {loading && data === null && (
          <p className="dashboard-panel__placeholder">
            <span className="spinner" />
            Đang tải...
          </p>
        )}
        {error && <p className="dashboard-panel__placeholder">{error}</p>}
        {!error && data && data.items.length === 0 && (
          <p className="dashboard-panel__placeholder">
            {hasActiveFilters ? "Không có bản ghi nào khớp bộ lọc." : "Chưa có dữ liệu đăng nhập."}
          </p>
        )}
        {!error && data && data.items.length > 0 && (
          <>
            <table className="log-table__table">
              <thead>
                <tr>
                  <th>Thời gian</th>
                  <th>Username</th>
                  <th>Kết quả</th>
                  <th title="Điểm rủi ro 0-100 của hybrid risk engine — một điểm duy nhất cho mỗi lần thử">Điểm</th>
                  <th>Hành động</th>
                  <th>Vị trí</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((event) => (
                  <tr key={event.id} className={rowClassName(event.hybrid_action)}>
                    <td>{new Date(event.created_at).toLocaleString("vi-VN")}</td>
                    <td>{event.user_id ? <Link to={`/dashboard/users/${event.user_id}`}>{event.attempted_username}</Link> : event.attempted_username}</td>
                    <td>{event.success ? "✅" : "❌"}</td>
                    <td>{event.hybrid_risk_score ?? "-"}</td>
                    <td>{actionLabel(event.hybrid_action)}</td>
                    <td>{event.city ? `${event.city}, ${event.country}` : "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="log-table__pagination">
              <button type="button" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                ← Trước
              </button>
              <span>
                Trang {page}/{totalPages} ({data.total} bản ghi)
              </span>
              <button type="button" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                Sau →
              </button>
            </div>
          </>
        )}
      </div>
    </section>
  );
}
