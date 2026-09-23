# SecureValidator — Phân tích lỗ hổng bảo mật trong `core.py`

> Bài tập: Cơ sở lập trình bảo mật – Kiểm tra dữ liệu đầu vào.
> Mục tiêu của README này **không phải** để sửa code, mà để **chỉ ra rằng module
> `core.py` — dù đặt tên là "Secure" và có docstring khẳng định "ngăn chặn"
> injection/SSRF/traversal — thực chất chứa nhiều lỗ hổng logic điển hình**, và trình
> bày cách khai thác từng lỗ hổng đó bằng dẫn chứng thực nghiệm (input → output thật,
> chạy trực tiếp trên `core.py` không sửa đổi).

## 1. Cấu trúc project

```
Lab1/
├── app.py
├── core.py             <-- đối tượng phân tích chính
├── index.html
├── test_validators.py
├── requirements.txt
├── render.yaml
└── .gitignore
```

`test_validators.py` chạy `python -m unittest test_validators` cho kết quả
**"Ran 10 tests ... OK"** — tức là toàn bộ unit test đều xanh. Đây chính là điểm mấu
chốt cần trình bày: **test pass không có nghĩa là an toàn**. Bộ test chỉ kiểm tra vài
case mẫu (`' OR 1=1 --`, `<script>alert("XSS")</script>`...), trong khi kẻ tấn công
không bị giới hạn ở những input đó.

---

## 2. `validate_url()` — SSRF: chỉ kiểm tra hình thức, không kiểm tra đích đến

```python
def validate_url(url: str) -> bool:
    """Validate URL and prevent basic SSRF vectors."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
    except Exception:
        return False
```

Docstring nói "prevent basic SSRF vectors" nhưng hàm **chỉ kiểm tra scheme và có
netloc hay không** — không hề resolve/so sánh host với danh sách mạng nội bộ
(loopback, link-local, private range, cloud metadata endpoint...).

**Bằng chứng chạy thực tế** (không sửa `core.py`, chỉ gọi hàm):

```
validate_url('http://127.0.0.1:6379/')                                     -> True
validate_url('http://169.254.169.254/latest/meta-data/...')                -> True
validate_url('http://[::1]:8080/admin')                                    -> True
validate_url('http://0177.0.0.1/')            # 127.0.0.1 dạng octal        -> True
validate_url('http://2130706433/')            # 127.0.0.1 dạng số nguyên    -> True
validate_url('http://localhost:5000/internal-api')                         -> True
validate_url('http://admin:pass@evil.com@trusted-looking.com/')            -> True
```

Tất cả đều được chấm **hợp lệ**. Nếu ứng dụng dùng kết quả này để cho phép server
tự fetch nội dung từ URL do người dùng nhập (webhook, "preview link", image proxy...),
kẻ tấn công có thể ép server gọi vào:
- Redis/DB nội bộ (`127.0.0.1:6379`),
- endpoint metadata của cloud (`169.254.169.254` — nơi thường lộ credentials tạm thời),
- dịch vụ chỉ mở trong mạng nội bộ mà lẽ ra không public.

→ Đây là **CWE-918 (SSRF)**. Cách làm đúng: dùng allowlist domain/scheme được phép,
resolve DNS rồi loại IP thuộc dải private/loopback/link-local trước khi cho phép, và
chặn lại request redirect sang địa chỉ nội bộ (DNS rebinding).

---

## 3. `sanitize_sql_input()` — blacklist keyword có thể bị lách hoàn toàn

```python
def sanitize_sql_input(input_str: str) -> str:
    sanitized = re.sub(r"(--|;|'|\"|#)", "", input_str)
    sanitized = re.sub(r"\b(OR|AND|SELECT|INSERT|DELETE|UPDATE|DROP|UNION|WHERE)\b",
                        "", sanitized, flags=re.IGNORECASE)
    return sanitized.strip()
```

Đây là lỗ hổng **nghiêm trọng nhất** trong toàn bộ file. Vấn đề gốc rễ: đây là
"chống SQL injection bằng cách xoá ký tự/từ khoá nguy hiểm" — một kỹ thuật mà
OWASP đã cảnh báo là **không bao giờ đủ**, thay vì dùng prepared statement/parameterized
query (nơi dữ liệu không bao giờ được nối trực tiếp vào câu lệnh SQL).

**Bằng chứng bypass bằng comment injection (`/**/`)** — vì `\b...\b` yêu cầu từ khoá
đứng một mình, ta chỉ cần chèn một comment SQL vào giữa từ khoá để nó không còn khớp
regex, nhưng khi đưa vào một số engine SQL (MySQL bỏ qua `/* */` khi parse), chuỗi
vẫn được hiểu là `UNION SELECT`:

```
input : '1 UN/**/ION SEL/**/ECT username,password FROM users'
output: '1 UN/**/ION SEL/**/ECT username,password FROM users'
```

**Không có gì bị xoá cả** — `UNION`, `SELECT` sống sót nguyên vẹn, chỉ vì bị tách đôi
bằng `/**/`. Hàm coi đây là "đã sanitize" và trả lại y nguyên chuỗi tấn công.

So sánh với payload sách giáo khoa (đã bị lọc đúng như test case của bài):

```
input : "' OR 1=1 --"
output: '1=1'
```

→ Với payload đơn giản, hàm hoạt động "có vẻ" đúng. Nhưng đó chính là cái bẫy: nó
tạo cảm giác an toàn giả (**false sense of security**) trong khi chỉ cần biến thể
nhỏ (`UN/**/ION`, hoặc dùng `||`, `XOR`, `LIKE`, `CASE WHEN`, `HAVING`... — những từ
khoá hoàn toàn không nằm trong blacklist) là bypass được.

→ CWE-89 (SQL Injection) / CWE-693 (Protection Mechanism Failure do dùng blacklist
thay vì allowlist/parameterization). Cách làm đúng duy nhất: **prepared statement**
(`cursor.execute("... WHERE id = %s", (user_input,))`) hoặc ORM có bind parameter —
không có bất kỳ hàm "làm sạch chuỗi" nào thay thế được điều này.

---

## 4. `validate_filename()` — chặn được traversal cơ bản, nhưng không toàn diện

```python
def validate_filename(filename: str) -> bool:
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return os.path.basename(filename) == filename
```

Đây là hàm **chắc chắn nhất trong file** — chặn `..`, `/`, `\` nên các payload
traversal dạng chuỗi thô (`../../etc/passwd`) bị từ chối đúng. Tuy nhiên:

```
validate_filename('report.pdf')                    -> True
validate_filename('../../etc/passwd')               -> False   (đúng)
validate_filename('..%2f..%2fetc%2fpasswd')          -> False   (đúng vì % không lọt basename check theo cách khác — nhưng lưu ý: nếu tầng trên decode %2f -> / TRƯỚC KHI gọi hàm này thì input thực nhận được đã là "../../etc/passwd")
validate_filename('file.txt\x00.jpg')                -> True   <-- LỌT
```

- Input chứa **null byte** (`\x00`) vẫn được coi là hợp lệ. Trên chính runtime Python
  hiện đại, việc này ít khai thác được trực tiếp vì `open()`/`os` sẽ tự raise lỗi khi
  gặp null byte — nhưng hàm `validate_filename` **vẫn nói dối rằng input này an toàn**,
  nghĩa là không thể tin tưởng hoàn toàn giá trị boolean trả về như một "chứng nhận an
  toàn" nếu dùng ở ngữ cảnh khác (thư viện C, hệ thống khác không tự chặn null byte).
- Hàm giả định input đưa vào **chưa qua decode**. Nếu framework phía trên (web
  server, proxy) tự động URL-decode trước khi truyền vào, một chuỗi ban đầu vô hại
  như `..%2f..%2f` có thể biến thành `../../` *sau* bước kiểm tra này ở một bước xử
  lý khác trong pipeline — đây là lỗi kiến trúc "decode sau validate" kinh điển, không
  nằm trong bản thân hàm nhưng là rủi ro khi tích hợp.

→ CWE-22 (residual). Khuyến nghị đúng: validate **sau cùng khi đã decode hết**, và
tốt nhất nên resolve đường dẫn tuyệt đối rồi kiểm tra nó có nằm trong thư mục gốc cho
phép hay không (`os.path.realpath(...).startswith(base_dir)`), thay vì chỉ lọc ký tự.

---

## 5. `validate_email()` — regex chỉ kiểm tra hình thức, không có giới hạn

```python
pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
return re.fullmatch(pattern, email) is not None
```

```
validate_email("user@example.com")                 -> True
validate_email("a"*300 + "@example.com")            -> True   (312 ký tự, không giới hạn độ dài)
validate_email("user@xn--80ak6aa92e.com")           -> True   (domain punycode/homograph)
```

- Không giới hạn độ dài → có thể dùng làm vector cho các cuộc tấn công tràn bộ đệm ở
  tầng khác, hoặc gửi input cực dài vào các hệ thống downstream (log, DB) gây lãng phí
  tài nguyên.
- `\w` trong Python mặc định khớp **Unicode** (chữ cái có dấu, ký tự nhìn giống chữ
  Latin — homoglyph), nên domain giả dạng (`pаypal.com` với `а` Cyrillic) vẫn có thể
  qua được bước "hợp lệ về hình thức", tạo điều kiện cho lừa đảo (phishing) nếu hệ
  thống hiển thị lại domain này mà không cảnh báo.
- Đây là lỗi **nhẹ nhất** trong file — về cơ bản validate hình thức email không phải
  là một control bảo mật, nhưng đáng nêu vì tên hàm/module gợi ý "đã an toàn".

→ CWE-20 (Improper Input Validation, mức độ thấp).

---

## 6. `sanitize_html_input()` — ổn trong ngữ cảnh hẹp, nhưng phụ thuộc nơi dùng

```python
def sanitize_html_input(html_str: str) -> str:
    return html.escape(html_str)
```

Đây là hàm **hợp lý nhất** — `html.escape()` là cách làm đúng chuẩn để chống XSS khi
giá trị được chèn vào **text node** của HTML (giữa hai thẻ). Tuy vậy:

- Nếu giá trị này bị chèn vào **ngữ cảnh khác** — thuộc tính HTML không có dấu ngoặc
  kép đúng cách, URL (`href="..."`), hoặc bên trong `<script>` — thì escape HTML đơn
  thuần **không đủ**, vì kẻ tấn công cần thoát khỏi ngữ cảnh JS/URL chứ không phải
  ngữ cảnh HTML. Hàm không biết & không thể biết nó sẽ được chèn vào đâu.
- Trong `index.html`, giá trị hiển thị qua `{{ results.html }}`. Jinja2 mặc
  định **tự động escape** cho file `.html` — nghĩa là kể cả khi `sanitize_html_input`
  có sai sót, tầng template vẫn escape lại một lần nữa (defense-in-depth tình cờ, không
  phải do thiết kế chủ đích của lab).

→ Không phải lỗ hổng nghiêm trọng, nhưng là ví dụ tốt để nói về **context-aware
escaping**: escape đúng phải phụ thuộc vào nơi dữ liệu được chèn vào, không có một
hàm "escape chung" nào dùng được cho mọi ngữ cảnh.

---

## 7. Vấn đề ở tầng ứng dụng (ngoài `core.py`)

- `app.py` chạy `app.run(debug=True)`. Chế độ debug của Flask/Werkzeug bật kèm
  **debugger console** (thấy rõ trong log gốc: `Debugger PIN: 993-054-488`) — nếu vô
  tình để `debug=True` khi deploy thật (không qua gunicorn), debugger console có thể
  bị lợi dụng để **thực thi mã tuỳ ý (RCE)** nếu lộ ra ngoài Internet.
- Form dùng `method="POST"` nhưng không có CSRF token → dễ bị **CSRF** ép người dùng
  đã đăng nhập gửi request thay họ (ảnh hưởng thấp ở lab demo này, nhưng là thói quen
  cần có nếu form thao túng dữ liệu thật).

---

## 8. Bảng tổng hợp

| Hàm | Có vẻ chống được | Thực tế | Mức độ | CWE |
|---|---|---|---|---|
| `validate_email` | Email sai định dạng | Không giới hạn độ dài, cho qua domain homograph | Thấp | CWE-20 |
| `validate_url` | SSRF ("prevent basic SSRF vectors") | Không chặn IP nội bộ/loopback/metadata, mọi host `http(s)` đều pass | **Cao** | CWE-918 |
| `validate_filename` | Path traversal | Ổn với chuỗi thô; rủi ro nếu decode xảy ra sau bước check, null byte "hợp lệ" | Trung bình | CWE-22 |
| `sanitize_sql_input` | SQL injection | Blacklist bị bypass hoàn toàn bằng comment injection (`UN/**/ION`) | **Nghiêm trọng** | CWE-89 |
| `sanitize_html_input` | XSS | Đúng cho ngữ cảnh text node; không đủ cho ngữ cảnh attribute/JS/URL | Thấp–Trung bình | CWE-79 |

## 9. Bài học chính để trình bày

1. **Test pass ≠ an toàn.** Bộ `test_validators.py` xanh 10/10 nhưng chỉ vì
   test case trùng khớp với đúng những gì hàm được viết để chặn.
2. **Blacklist (chặn từ khoá/ký tự đã biết) luôn có thể bị lách** — điểm yếu cốt lõi
   của `sanitize_sql_input`. Giải pháp đúng cho SQL injection không phải là "lọc chuỗi
   sạch hơn" mà là đổi hẳn cách tiếp cận sang **parameterized query**.
3. **"Validate" và "escape đúng ngữ cảnh nơi dùng"** là hai việc khác nhau —
   `validate_url` sai vì kiểm tra hình thức URL chứ không kiểm tra đích mạng thực sự
   mà server sẽ gọi tới.
4. Một hàm tên là `secure_*`/`validate_*`/`sanitize_*` **không tự động an toàn** — luôn
   phải tự kiểm chứng bằng cách thử input độc hại thực tế, như đã làm ở các mục 2–6.

---

*Ghi chú: `core.py`, `requirements.txt`, `.gitignore`, `index.html` được chép lại
nguyên văn từ tài liệu thực hành (ban đầu tổ chức thành package `securevalidator/` +
`templates/`, sau đó được gộp phẳng vào `Lab1/` theo yêu cầu). `app.py` không xuất
hiện rõ trong tài liệu (chỉ thấy log chạy chương trình) nên được viết lại tối giản để
khớp với `index.html` và các hàm trong `core.py`, phục vụ mục đích chạy thử và kiểm
chứng các PoC ở trên — phần này không phải chụp lại 1:1 từ tài liệu gốc.*
