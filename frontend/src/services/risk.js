// MR23 — một điểm rủi ro và một hành động cho mỗi lần thử, một cảnh báo cho mỗi sự cố. Các tiện ích dùng chung để mọi
// khu vực của dashboard đọc dữ liệu mới theo cùng một cách (không còn `alert_type`, `risk_score`/`ml_anomaly_score` của
// lần thử).

export const ACTION_LABELS = {
  allow: "Cho qua",
  alert: "Cảnh báo",
  step_up: "Xác thực thêm",
  lock: "Khoá",
};

export function actionLabel(action) {
  return ACTION_LABELS[action] ?? "-";
}

// Mức màu dùng lại lớp CSS có sẵn từ Tuần 4: allow -> thấp, alert -> trung bình, step_up/lock -> cao.
export function actionLevel(action) {
  if (action === "step_up" || action === "lock") return "high";
  if (action === "alert") return "medium";
  if (action === "allow") return "low";
  return null;
}

// Hành động nặng nhất của sự cố; cảnh báo cũ hơn MR23 không có thông tin này.
export function incidentAction(alert) {
  return alert?.explanation?.action ?? null;
}

// Tiêu đề ngắn của cảnh báo: họ tấn công gợi ý; cảnh báo cũ hơn MR23 dùng loại gốc đã lưu khi gộp loại cảnh báo.
export function alertTitle(alert) {
  return alert?.attack_family ?? alert?.explanation?.legacy_alert_type ?? "Cảnh báo";
}

// Đường bay của luật di chuyển bất khả thi: hai đầu nằm trong bằng chứng ĐÃ LƯU của cảnh báo, nên vẽ lại được cả sau khi
// tải lại trang (trước MR23 chỉ có trong payload WebSocket).
export function travelLine(alert) {
  const travel = alert?.explanation?.evidence?.impossible_travel;
  if (!travel) return null;
  const { previous_latitude, previous_longitude, latitude, longitude } = travel;
  if ([previous_latitude, previous_longitude, latitude, longitude].some((v) => v === null || v === undefined)) return null;
  return { from: [previous_latitude, previous_longitude], to: [latitude, longitude] };
}

const GROUP_LABELS = { ml: "mô hình", rule: "luật", reputation: "danh tiếng" };

export function evidenceGroupLabel(group) {
  return GROUP_LABELS[group] ?? group;
}
