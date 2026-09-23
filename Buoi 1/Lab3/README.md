# SecureLogger — Phân tích lỗ hổng bảo mật trong `logger.py`

> Bài tập: Cơ sở lập trình bảo mật – Ghi nhật ký ưu tiên bảo mật.
> Mục tiêu của README này **không phải** để sửa code, mà để **chỉ ra rằng "SecureLogger"
> — hệ thống ghi log tự nhận có "tự động phát hiện và che dấu PII" cùng "phát hiện thay
> đổi trái phép (tamper detection)" — thực chất có những lỗ hổng khiến đúng hai tính năng
> quảng cáo đó không hoạt động như mong đợi**, và chứng minh bằng cách chạy thật ứng dụng
> Flask (`app.py` + `logger.py`, không sửa đổi) qua HTTP, y hệt cách demo trong tài liệu.

## 1. SecureLogger là gì

`logger.py` cung cấp `secure_logger` — một `logging.Logger` ghi ra `secure.log` dạng
JSON, tự động:
1. Che (`mask_pii`) các trường trông giống PII (email, token/apikey/key/password)
   trước khi ghi.
2. Luân phiên log khi vượt `MAX_LOG_SIZE`, nén bằng gzip (`GZipRotator`).
3. Ghi một "chữ ký" SHA-256 của mỗi dòng log vào `secure.log.sig` để sau này kiểm tra
   log có bị sửa hay không (`append_signature`).

`app.py` (Flask) gọi lại `securevalidator` (Lab1) ở endpoint `/validate`, rồi log cả
`data` (input thô của người dùng) và `results` (kết quả kiểm tra) qua `secure_logger.info(...,
extra={"data": data, "results": results})`.

---

## 2. `mask_pii()` không che được `password`/`token`/`api_key` — dù đó chính là mục tiêu chính

```python
PII_PATTERNS = {
    "email": r'[\w\.-]+@[\w\.-]+\.\w+',
    "token": r'(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{8,}["\']?',
}
```

Pattern `"token"` được viết để bắt cú pháp **gán biến trong mã nguồn** kiểu
`password = "hunter2"` (có dấu `=`). Nhưng dữ liệu thực sự được đưa vào `mask_pii()`
trong `JSONFormatter` không phải mã nguồn — nó là **`str(dict)`** của `data`/`results`
đến từ JSON request, tức có dạng `{'password': 'hunter2', ...}` — dùng dấu **`:`**, không
phải `=`. Hai cú pháp này không bao giờ khớp nhau.

**Bằng chứng — chạy thật `app.py` qua Flask test client, gửi request có `password` và
`api_key` (tài liệu gốc không test trường hợp này, chỉ test email/url/filename/sql/html):**

```python
client.post("/validate", json={
    "email": "admin@corp.com", "password": "hunter2",
    "api_key": "sk_live_51H8xJ2eZvKYlo2C0", ...
})
```

Nội dung **thật** ghi vào `secure.log`:

```json
{"timestamp": "...", "level": "INFO", "message": "Validation check performed",
 "data": "{'api_key': 'sk_live_51H8xJ2eZvKYlo2C0', 'email': '<email_masked>',
           ..., 'password': 'hunter2', ...}",
 "results": "..."}
```

`email` được che đúng thành `<email_masked>` (vì pattern email không cần dấu `=`, chỉ
cần chuỗi giống email), nhưng **`password: 'hunter2'` và `api_key:
'sk_live_51H8xJ2eZvKYlo2C0'` bị ghi thẳng ra file log, hoàn toàn không che** — đúng thứ
mà tính năng này được quảng cáo là bảo vệ. Vì test case duy nhất trong tài liệu (trang
31) không có trường `password`/`token`/`apikey` nào, lỗi này không bao giờ lộ ra trong
demo gốc.

---

## 3. `secure.log.sig` không phải "chữ ký" — chỉ là hash trần, ai cũng giả được

```python
def hash_line(line):
    return hashlib.sha256(line.encode('utf-8')).hexdigest()

def append_signature(line):
    with open(SIGNATURE_FILE, "a", encoding="utf-8") as f:
        f.write(hash_line(line))
```

Đây là **SHA-256 không khoá** (unkeyed hash), không phải HMAC hay chữ ký số. Một "chữ
ký" đúng nghĩa để chống giả mạo cần một bí mật (khoá HMAC, hoặc private key) mà kẻ tấn
công không có — nếu không, **bất kỳ ai có quyền ghi vào `secure.log` cũng tự tính lại
được `secure.log.sig` khớp với nội dung đã sửa**, vì thuật toán tạo "chữ ký" hoàn toàn
công khai và không cần khoá.

**Bằng chứng:**

```
Dòng log thật:        {"...", "message": "User admin balance = 1000"}
Chữ ký (sha256) thật:  93e4059e824f3b9667537ded1d1bcefca3b01f5f5baf2dc4301234db04b83746...

--- Kẻ tấn công sửa trực tiếp cả 2 file ---
Dòng log đã sửa:      {"...", "message": "User admin balance = 999999999"}
Chữ ký kẻ tấn công tự tính lại: f3a179e23c3b57dc0d5a20f16a49ff603fb32c34aac19352e2322f6...
```

Chữ ký "giả" này **hợp lệ 100%** theo đúng cách `hash_line()` định nghĩa — vì không có
bước nào trong hệ thống dùng một bí mật mà kẻ tấn công không truy cập được. Tamper
detection thật sự cần `hmac.new(SECRET_KEY, line, hashlib.sha256)` (khoá bí mật lưu
riêng, không nằm trong repo/máy bị tấn công) hoặc chữ ký số bất đối xứng — không phải
hash trần.

---

## 4. `secure.log.sig` không có ký tự phân tách — và không được xoay vòng cùng log

```python
f.write(hash_line(line))   # không có "\n" ở cuối
```

**Bằng chứng** — ghi liên tiếp cho 2 request thật ở trên, `secure.log.sig` dài đúng
**128 ký tự = 2 × 64** (mỗi SHA-256 hex dài 64 ký tự), nối liền nhau không dấu phân
cách:

```
a4a0934226e24a370f32b43adcfec600742a02f6ca55fadffe99d20a31c0e962f5219bba6aea8...
```

Về lý thuyết vẫn tách được vì độ dài cố định, nhưng không có gì (không index, không
timestamp) neo một hash với đúng dòng log nào — và khi `GZipRotator` xoay
`secure.log` thành `secure.log.1.gz`, **`secure.log.sig` không hề được xoay theo**: nó
tiếp tục phình to vô hạn, tách rời khỏi việc file log nào (hiện tại hay đã nén) tương
ứng với hash nào trong đó.

---

## 5. Các vấn đề nhỏ hơn

- `app.run(debug=True)`: lặp lại đúng vấn đề đã nêu ở Lab1 — debugger console của
  Werkzeug (`Debugger PIN` xuất hiện trong log gốc) có thể bị lợi dụng để thực thi mã
  tuỳ ý nếu vô tình để chế độ debug khi expose ra ngoài.
- `request.get_json(force=True)`: bỏ qua hoàn toàn kiểm tra `Content-Type`, chấp nhận
  parse JSON dù client gửi sai header — không phải lỗ hổng nghiêm trọng, nhưng làm mất
  một lớp kiểm tra "well-formed request" cơ bản.
- Việc che PII chỉ xảy ra **trong `JSONFormatter.format()`** — tức là một đặc tính phụ
  của việc format log, không phải một bước sanitize độc lập trước khi dữ liệu trở thành
  `LogRecord`. Nếu sau này có thêm handler khác không gán `JSONFormatter`, dữ liệu gốc
  chưa che sẽ bị ghi ra nguyên văn ở đó.

---

## 6. Bảng tổng hợp

| Tính năng quảng cáo | Cơ chế | Thực tế (đã kiểm chứng) | Mức độ |
|---|---|---|---|
| Che PII (password/token/apikey) | Regex `key\s*=\s*value` | Không khớp cú pháp `str(dict)` (`'key': 'value'`) → **không bao giờ che** | **Nghiêm trọng** |
| Che PII (email) | Regex dạng email tự do | Hoạt động đúng (không phụ thuộc cú pháp `=`) | — |
| Tamper detection (`secure.log.sig`) | SHA-256 của từng dòng | Hash trần không khoá → ai ghi được file đều tự tạo được chữ ký hợp lệ | **Nghiêm trọng** |
| Toàn vẹn `secure.log.sig` qua thời gian | Ghi nối tiếp | Không có delimiter, không xoay vòng cùng `secure.log` khi nén | Trung bình |
| Debug mode khi chạy | `app.run(debug=True)` | Lộ Werkzeug debugger console | Trung bình |

## 7. Bài học chính để trình bày

1. **Test case trong tài liệu quyết định lỗi nào "được nhìn thấy".** Demo gốc chỉ gửi
   `email/url/filename/sql/html` — không có `password`/`token` — nên lỗi che PII
   nghiêm trọng nhất chưa từng bị phát hiện qua chính quy trình test được hướng dẫn.
   Đây là lý do luôn phải tự nghĩ ra test case "trái ngành" thay vì chỉ chạy lại đúng
   ví dụ có sẵn — giống bài học ở Lab1 và Lab2.
2. **"Hash" và "chữ ký" (signature) không phải một khái niệm** — một cơ chế chống giả
   mạo chỉ có giá trị nếu kẻ tấn công **không thể** tự tạo ra output hợp lệ; thiếu khoá
   bí mật (HMAC) hoặc private key, một "chữ ký" chỉ là checksum chống lỗi ngẫu nhiên,
   không chống được người cố ý sửa dữ liệu.
3. **Che dữ liệu (masking) phải khớp với hình dạng thật của dữ liệu tại điểm áp dụng**
   — viết regex theo cú pháp mã nguồn (`key = value`) rồi áp dụng lên cú pháp khác
   (`str(dict)`, JSON, YAML...) là một lớp lỗi rất dễ mắc và rất khó nhận ra nếu không
   test bằng dữ liệu thật.

---

*Ghi chú: `logger.py`, `app.py`, `requirements.txt` được chép lại nguyên văn từ tài
liệu thực hành. Theo cấu trúc gốc, `logger.py` nằm trong package
`securelogger/logger.py` và `app.py` import qua `securevalidator`/`securelogger` — ở
đây được đặt phẳng trong `Lab3/` và import trực tiếp `core`/`logger` để nhất quán với
cách trình bày ở Lab1/Lab2 (`core.py` là bản sao của `core.py` trong Lab1, đúng như
hướng dẫn gốc "Sao chép các file từ secure-validator-lab/securevalidator sang
secure_logger_lab/securevalidator"). Toàn bộ log mẫu và kết quả hash ở trên là output
thật khi chạy `app.py` qua Flask test client (không sửa đổi `logger.py`), không phải
suy đoán.*
