"""MR31 — kiểm chứng PHƯƠNG PHÁP phát hiện trên log xác thực THẬT của LANL ("Comprehensive, Multi-Source Cyber-Security Events",
A. D. Kent, Los Alamos National Laboratory, 2015, doi:10.17021/1179829).

Đây là log đăng nhập Windows của mạng nội bộ (Kerberos/NTLM, máy tính nguồn → máy đích), KHÔNG phải log web; không nối vào `/login`. Mục đích
duy nhất: kiểm tra cách tiếp cận của hệ thống (đặc trưng "mới với chính tài khoản" + đếm trong cửa sổ + Isolation Forest không giám sát + luật
đơn giản) có bắt được tấn công thật (sự kiện red team có nhãn) hay không, đo trên dữ liệu không do nhóm tạo ra."""
