import axios from "axios";

import { clearAdminToken, getAdminToken } from "./auth";

// Địa chỉ backend — cấu hình qua biến môi trường VITE_API_BASE_URL (xem .env.example ở gốc repo).
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
});

// Route công khai — không gửi JWT quản trị kèm theo (MR34: trước đó mọi request, kể cả đăng nhập của web app mẫu, đều mang
// token quản trị nếu trình duyệt đang đăng nhập dashboard).
const PUBLIC_PATHS = new Set(["/login", "/login/verify-otp", "/admin/login"]);

// Tự đính JWT admin (nếu có) vào request tới route quản trị (GET /login-events, GET /alerts... — yêu cầu từ Tuần 5,
// nhiệm vụ 5.1).
apiClient.interceptors.request.use((config) => {
  const token = getAdminToken();
  if (token && !PUBLIC_PATHS.has(config.url)) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// MR32: token hết hạn / không còn hợp lệ (backend khởi động lại với khoá JWT mới) -> xoá token và về trang đăng nhập quản
// trị, thay vì để dashboard im lặng báo lỗi tải dữ liệu. MR34: chỉ khi chính request bị 401 có mang token — 401 "sai mật
// khẩu" của trang đăng nhập web app (cùng trình duyệt) từng làm quản trị viên đang xem dashboard bị đăng xuất.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && error.config?.headers?.Authorization) {
      clearAdminToken();
      window.location.assign("/admin/login");
    }
    return Promise.reject(error);
  },
);
