# Lab 3 — SecureLogger: Phân tích điểm yếu của `logger.py`

> **Mục tiêu:** Không sửa code, mà **chứng minh** rằng hệ thống log "SecureLogger" —
> quảng cáo "tự động che PII" và "phát hiện thay đổi trái phép (tamper detection)" —
> có lỗ hổng khiến đúng hai tính năng đó không hoạt động như hứa.
> Mỗi mục: **Code → Cách bypass → Kết quả chạy thật → Nguyên nhân**. Output là kết quả
> chạy thật `app.py` (Flask) qua HTTP, y hệt cách demo trong tài liệu.

## Cấu trúc

```
Lab3/
├── logger.py           <-- đối tượng phân tích
├── app.py  core.py     (core.py sao chép từ Lab1)
├── requirements.txt  .gitignore
```

---

## 1. Bypass `mask_pii()` → Mật khẩu / token ghi thẳng ra log

### Code
```python
PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{8,}["\']?',
}
```

### Bypass
Pattern `"token"` viết để bắt cú pháp **mã nguồn** `password = "..."` (dấu `=`). Nhưng
dữ liệu thật đưa vào `mask_pii()` là **`str(dict)`** từ JSON request — dạng
`{'password': 'hunter2'}` dùng dấu **`:`**, không phải `=`. Hai cú pháp không bao giờ khớp.

### Kết quả chạy thật
```python
# gửi request có password + api_key (tài liệu gốc KHÔNG test trường hợp này)
client.post("/validate", json={
    "email": "admin@corp.com", "password": "hunter2",
    "api_key": "sk_live_51H8xJ2eZvKYlo2C0", ...})
```
Nội dung **thật** ghi vào `secure.log`:
```json
{"level": "INFO", "message": "Validation check performed",
 "data": "{'api_key': 'sk_live_51H8xJ2eZvKYlo2C0', 'email': '<email_masked>',
           'password': 'hunter2', ...}", ...}
```
→ `email` che đúng (`<email_masked>`), nhưng **`password: 'hunter2'` và `api_key:
'sk_live_...'` ghi thẳng, không che**.

### Nguyên nhân
Regex viết cho cú pháp `key = value` nhưng áp lên `str(dict)` là `'key': 'value'`. Vì
test mẫu trong sách (trang 31) không có trường `password`/`token` nào, lỗi này chưa bao
giờ lộ trong demo. → mask phải khớp **hình dạng thật của dữ liệu** tại điểm áp dụng.

---

## 2. Bypass tamper detection → "Chữ ký" `secure.log.sig` giả được

### Code
```python
def hash_line(line):
    return hashlib.sha256(line.encode('utf-8')).hexdigest()   # HASH TRẦN, không khoá
```

### Bypass
Vì "chữ ký" chỉ là SHA-256 không khoá (không HMAC, không private key), **ai sửa được
`secure.log` cũng tự tính lại được `secure.log.sig` khớp với nội dung đã sửa**.

### Kết quả chạy thật
```
Dòng log thật:        {"...", "message": "User admin balance = 1000"}
Chữ ký sha256 thật:    93e4059e824f3b9667537ded1d1bcefca3b01f5f5baf2dc4301234db04b83746

--- Kẻ tấn công sửa cả 2 file (không cần biết khoá nào) ---
Dòng log đã sửa:      {"...", "message": "User admin balance = 999999999"}
Chữ ký tự tính lại:    f3a179e23c3b57dc0d5a20f16a49ff603fb32c34aac19352e2322f6c128cb06c
```
→ Chữ ký "giả" **hợp lệ 100%** theo đúng cách `hash_line()` định nghĩa.

### Nguyên nhân
Một cơ chế chống giả mạo chỉ có giá trị nếu kẻ tấn công **không thể** tự tạo output hợp
lệ. Thiếu khoá bí mật, "chữ ký" chỉ là checksum chống lỗi ngẫu nhiên, không chống người
cố ý. Cách đúng: `hmac.new(SECRET_KEY, line, sha256)` (khoá lưu riêng) hoặc chữ ký số.

---

## 3. `secure.log.sig` không có dấu phân cách và không xoay vòng

### Code
```python
f.write(hash_line(line))   # không có "\n" ở cuối
```

### Kết quả chạy thật
```
$ wc -c secure.log.sig        # sau 2 dòng log
128 secure.log.sig            # = 2 x 64 ký tự, nối liền không dấu phân cách
a4a0934226e24a...962f5219bba6aea813e775df4a75e2d882de37b7d17b58972794bf21ca4411848fd
```

### Nguyên nhân
Không có delimiter, không index/timestamp neo hash với dòng log nào. Khi `GZipRotator`
nén `secure.log` → `secure.log.1.gz`, file `.sig` **không được xoay theo** mà phình vô
hạn, tách rời khỏi file log tương ứng → không thể xác thực đáng tin sau khi rotate.

---

## 4. Vấn đề nhỏ hơn

- `app.run(debug=True)`: Werkzeug debugger console (RCE nếu expose) — lặp lại từ Lab1.
- `request.get_json(force=True)`: bỏ qua kiểm tra `Content-Type`, parse mọi body → mất
  một lớp kiểm tra request cơ bản.
- Việc che PII chỉ xảy ra trong `JSONFormatter.format()` — nếu thêm handler khác không
  gán `JSONFormatter`, dữ liệu gốc chưa che sẽ bị ghi nguyên văn ở đó.

---

## 5. Bảng tổng hợp

| Tính năng quảng cáo | Cơ chế | Thực tế (đã kiểm chứng) | Mức độ |
|---|---|---|---|
| Che PII (password/token) | Regex `key = value` | Không khớp `str(dict)` (`'key': 'value'`) → **không che** | **Nghiêm trọng** |
| Che PII (email) | Regex email tự do | Hoạt động đúng | — |
| Tamper detection | SHA-256 từng dòng | Hash trần không khoá → giả được | **Nghiêm trọng** |
| Toàn vẹn `.sig` theo thời gian | Ghi nối tiếp | Không delimiter, không rotate cùng log | Trung bình |
| Debug mode | `app.run(debug=True)` | Lộ Werkzeug debugger | Trung bình |

## 6. Bài học chính

1. **Test case trong tài liệu quyết định lỗi nào được nhìn thấy** — demo gốc không gửi
   `password`/`token` nên lỗi che PII nghiêm trọng nhất chưa từng bị phát hiện.
2. **"Hash" ≠ "chữ ký (signature)"** — thiếu khoá bí mật (HMAC/private key), một "chữ
   ký" chỉ chống lỗi ngẫu nhiên, không chống người cố ý sửa dữ liệu.
3. **Masking phải khớp hình dạng thật của dữ liệu** — viết regex theo cú pháp mã nguồn
   rồi áp lên `str(dict)`/JSON/YAML là lỗi rất dễ mắc, rất khó thấy nếu không test bằng
   dữ liệu thật.

---

*Ghi chú: `logger.py`, `app.py`, `requirements.txt` chép nguyên văn từ tài liệu. Cấu
trúc gốc là package `securelogger/` + `securevalidator/`; ở đây gộp phẳng vào `Lab3/` và
import trực tiếp `core`/`logger` để nhất quán với Lab1/Lab2 (`core.py` là bản sao từ
Lab1, đúng hướng dẫn "sao chép từ secure-validator-lab/securevalidator"). Toàn bộ log
mẫu và hash là output thật khi chạy `app.py` qua Flask test client, không sửa `logger.py`.*
