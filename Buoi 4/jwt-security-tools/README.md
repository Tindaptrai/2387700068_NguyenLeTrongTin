# JWT Security Tools

Tác giả: Nguyen Le Trong Tin · MSSV: 2387700068 · Lab 04.

Project Python thực hành xác minh JWT HS256/`exp`, quản lý access/refresh token, tạo OAuth Authorization Code URL kèm PKCE S256, API gateway Flask loopback và kiểm tra offline danh sách khóa ứng viên có giới hạn 1.000 dòng.

## Chạy nhanh trên Windows PowerShell

```powershell
cd ".\Buoi 4\jwt-security-tools"
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:JWT_SECRET = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
.\.venv\Scripts\python.exe .\main.py --serve
```

Gateway lắng nghe tại <http://127.0.0.1:5000>. Tài khoản demo cục bộ là `student` / `lab-password`. Dừng bằng `Ctrl+C`. Chạy tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Xem [README Buổi 4](../README.md) để đọc vai trò từng module, lệnh thử API và ảnh kết quả. Chỉ dùng token/ứng dụng thuộc lab được phép. Cracker chỉ chạy offline và giới hạn 1.000 ứng viên; refresh token được giữ trong RAM, vì vậy đây là ví dụ học tập chứ không phải dịch vụ production.
