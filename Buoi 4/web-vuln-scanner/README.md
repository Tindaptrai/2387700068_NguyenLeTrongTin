# Web Vulnerability Scanner

Tác giả: Nguyen Le Trong Tin · MSSV: 2387700068 · Lab 04.

Scanner Python gồm kiểm tra tín hiệu XSS phản chiếu, lỗi SQL phổ biến, các tín hiệu CSRF cơ bản và lỗi fetch SSRF phản chiếu. Có CLI tạo báo cáo JSON và giao diện Flask cục bộ. Scanner giới hạn mục tiêu mặc định ở localhost/loopback; hostname khác cần khai báo trước trong `LAB_ALLOWED_HOSTS`.

## Chạy nhanh trên Windows PowerShell

```powershell
cd ".\Buoi 4\web-vuln-scanner"
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m ui.app
```

Mở <http://127.0.0.1:5001> và nhập URL của ứng dụng lab đang chạy trên máy. Dừng bằng `Ctrl+C`. Chạy CLI bằng lệnh sau, thay `PORT` bằng cổng mục tiêu lab được phép:

```powershell
.\.venv\Scripts\python.exe .\main.py http://127.0.0.1:PORT/ --output .\report.json
```

Chạy tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Xem [README Buổi 4](../README.md) để đọc giải thích module, cách giới hạn phạm vi và ảnh kết quả. Chỉ dùng với localhost hoặc hệ thống bạn có quyền kiểm thử. Đây là scanner tín hiệu cơ bản, không phải chứng nhận bảo mật.
