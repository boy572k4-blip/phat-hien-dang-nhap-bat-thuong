import axios from "axios";

import { clearAdminToken, getAdminToken } from "./auth";

// Địa chỉ backend — cấu hình qua biến môi trường VITE_API_BASE_URL (xem .env.example ở gốc repo).
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
});

// Tự đính JWT admin (nếu có) vào mọi request — các route quản trị
// (GET /login-events, GET /alerts) yêu cầu từ Tuần 5 (nhiệm vụ 5.1).
apiClient.interceptors.request.use((config) => {
  const token = getAdminToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// MR32: token hết hạn / không còn hợp lệ (backend khởi động lại với khoá JWT mới) -> xoá token và về trang đăng nhập quản
// trị, thay vì để dashboard im lặng báo lỗi tải dữ liệu. Không áp cho chính /admin/login (sai mật khẩu cũng là 401).
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const url = error.config?.url ?? "";
    if (error.response?.status === 401 && getAdminToken() && url !== "/admin/login") {
      clearAdminToken();
      window.location.assign("/admin/login");
    }
    return Promise.reject(error);
  },
);
