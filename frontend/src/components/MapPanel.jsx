import L from "leaflet";
import markerIcon2x from "leaflet/dist/images/marker-icon-2x.png";
import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";
import { useEffect, useState } from "react";
import { MapContainer, Marker, Polyline, TileLayer, useMap } from "react-leaflet";

import { apiClient } from "../services/api";
import { travelLine } from "../services/risk";

// Fix icon marker mặc định của Leaflet bị vỡ khi bundler (Vite) không tự
// resolve đúng đường dẫn ảnh — lỗi rất phổ biến với react-leaflet.
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: markerIcon2x,
  iconUrl: markerIcon,
  shadowUrl: markerShadow,
});

// Tự động pan/zoom để LUÔN thấy được cả 2 điểm khi có đường bay mới — nếu
// không, khung nhìn mặc định (center Việt Nam, zoom 5) sẽ cắt mất điểm ở
// xa (VD Mỹ/Úc) khiến trông như bản đồ không vẽ gì (đã gặp thật khi test
// kịch bản impossible_travel ở Tuần 6, không phải lỗi vẽ mà là lỗi khung nhìn).
function FitBoundsOnChange({ bounds }) {
  const map = useMap();

  useEffect(() => {
    if (!bounds) return;
    map.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
  }, [bounds, map]);

  return null;
}

// Khu vực bản đồ (nhiệm vụ 3.4) — vẽ hai điểm + đường nối của lần di chuyển
// bất khả thi gần nhất. MR23: hai đầu đường bay đọc từ bằng chứng ĐÃ LƯU của
// cảnh báo (`explanation.evidence.impossible_travel`) — cả khi nhận qua
// WebSocket (nhiệm vụ 5.3) lẫn khi mở/tải lại trang (lấy từ các cảnh báo gần
// đây), không còn phụ thuộc loại cảnh báo hay payload riêng.
export default function MapPanel({ latestAlert }) {
  const [line, setLine] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiClient
      .get("/alerts", { params: { sort: "recent", page_size: 50 } })
      .then((res) => {
        const recent = res.data.items.map(travelLine).find(Boolean);
        if (!cancelled && recent) setLine((current) => current ?? recent);
      })
      .catch(() => {}); // bản đồ vẫn dùng được khi không tải được lịch sử, chỉ chưa có đường bay cũ
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const latest = travelLine(latestAlert);
    if (latest) setLine(latest);
  }, [latestAlert]);

  return (
    <section className="dashboard-panel" aria-label="Bản đồ đăng nhập">
      <h2>Bản đồ</h2>
      <div className="dashboard-panel__body">
        <MapContainer center={[16.0, 106.0]} zoom={5} style={{ height: "100%", width: "100%" }}>
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          {line && (
            <>
              <Marker position={line.from} />
              <Marker position={line.to} />
              <Polyline positions={[line.from, line.to]} pathOptions={{ color: "red" }} />
              <FitBoundsOnChange bounds={[line.from, line.to]} />
            </>
          )}
        </MapContainer>
      </div>
    </section>
  );
}
