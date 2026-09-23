# GitSecure — Phân tích lỗ hổng bảo mật trong `pre-commit`

> Bài tập: Cơ sở lập trình bảo mật – Thực hành bảo mật trước khi commit (pre-commit hook).
> Mục tiêu của README này **không phải** để sửa code, mà để **chỉ ra rằng "GitSecure" —
> một pre-commit hook được quảng cáo là "tự động ngăn chặn rủi ro bảo mật" — thực chất
> có nhiều điểm mù nghiêm trọng**, và chứng minh từng điểm bằng thực nghiệm (chạy trực
> tiếp trên `pre-commit` không sửa đổi, có đối chiếu với Bandit chạy độc lập).

## 1. GitSecure là gì

`pre-commit` là một Python script được gắn vào Git qua `git config core.hooksPath
.githooks`, tự động chạy mỗi khi `git commit`. Nó gồm 3 lớp kiểm tra trên các file đã
`git add` (staged):

1. `scan_sensitive()` — dò tìm API key/secret/password/token hardcode bằng regex.
2. `check_permissions()` — cảnh báo file có quyền ghi cho "other" (world-writable).
3. `run_bandit()` — chạy Bandit để tìm lỗ hổng mã nguồn, chặn nếu có phát hiện `High`.

Nếu có bất kỳ `findings`, hook in `"COMMIT BLOCKED by GitSecure"`, ghi log vào
`gitsecure.log`, và `sys.exit(1)` để Git huỷ commit.

---

## 2. `run_bandit()` — tích hợp Bandit **không bao giờ hoạt động**

```python
result = subprocess.run(["bandit", "-r", "."], capture_output=True, text=True)
if "SEVERITY: High" in result.stdout:
    ...
```

Đây là lỗi nghiêm trọng nhất, và dễ kiểm chứng nhất: chuỗi cần so khớp là
**`"SEVERITY: High"` (toàn chữ hoa)**, nhưng Bandit không bao giờ in ra như vậy.

**Bằng chứng — chạy Bandit thật trên file có lỗi High/High** (`import telnetlib` — một
plugin Bandit chấm điểm High/High):

```
$ bandit -r .
   Severity: Low    Confidence: Medium
   Severity: High   Confidence: High
   Severity: High   Confidence: High
```

Bandit luôn in `"Severity: High"` (chỉ chữ **S** viết hoa) — không bao giờ khớp với
chuỗi `"SEVERITY: High"` mà hook tìm. Hệ quả: **điều kiện `if "SEVERITY: High" in
result.stdout` luôn là `False`, vĩnh viễn, bất kể Bandit tìm thấy bao nhiêu lỗi
High.** Toàn bộ mục tiêu "Quét lỗ hổng cơ bản bằng Bandit" trong yêu cầu đề bài coi
như không tồn tại trên thực tế — code chạy, không báo lỗi, nhưng không kiểm tra được
gì cả. Đây là ví dụ kinh điển của "silent failure": không có exception, không có cảnh
báo, hook vẫn chạy "bình thường" và luôn in `GitSecure: All checks passed.`.

---

## 3. `scan_sensitive()` — regex chỉ bắt được đúng format viết trong sách

```python
r"apikey\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
r"secret\s*=\s*['\"][A-Za-z0-9_\-]{8,}['\"]",
r"password\s*=\s*['\"][^'\"]{4,}['\"]",
r"token\s*=\s*['\"][A-Za-z0-9]{10,}['\"]",
r"(AKIA|ASIA)[A-Z0-9]{16}",
```

Vấn đề: mỗi pattern yêu cầu **từ khoá đứng ngay sát trước `=`** (chỉ cách bởi khoảng
trắng) và giá trị **phải nằm trong dấu nháy**. Đây là kiểu code thực tế phổ biến nhất
(snake_case, không quote số, YAML/dict...) lại không khớp:

**Bằng chứng chạy thực tế:**

```
BỊ PHÁT HIỆN              | password = "123456"                       (payload mẫu trong sách)
BYPASS - KHÔNG PHÁT HIỆN  | api_key = "sk_test_4242424242424242"      (snake_case — style phổ biến nhất)
BYPASS - KHÔNG PHÁT HIỆN  | SECRET_KEY_2 = "django-insecure-..."      (biến có hậu tố số)
BYPASS - KHÔNG PHÁT HIỆN  | token = "eyJhbGci....xVmNHl0w..."         (JWT thật — có dấu chấm)
BYPASS - KHÔNG PHÁT HIỆN  | password = 123456                         (không có dấu nháy)
BYPASS - KHÔNG PHÁT HIỆN  | password: "SuperSecret123"                (kiểu YAML/dict, dùng dấu :)
```

- `api_key`, `SECRET_KEY_2`: `\s*` chỉ khớp khoảng trắng, **không khớp dấu gạch dưới**
  giữa từ khoá và phần còn lại của tên biến → chỉ cần đặt tên biến hơi khác chuẩn
  "apikey"/"secret" viết liền là né được hoàn toàn.
- Token dạng JWT thật luôn chứa dấu `.` (phân tách header/payload/signature), trong khi
  pattern yêu cầu toàn bộ chuỗi trong ngoặc kép chỉ gồm `[A-Za-z0-9]` → **token thật sự
  nguy hiểm nhất lại là loại né được dễ nhất**.
- Giá trị không đặt trong dấu nháy (số nguyên, biến khác) hoặc dùng cú pháp YAML
  (`key: value`) đều lọt qua vì pattern cứng yêu cầu `=` và dấu nháy.

→ Đây là danh sách **blacklist theo mẫu cố định**, không phải nhận diện ngữ nghĩa —
cùng một lỗi tư duy như `sanitize_sql_input` ở Lab1: chỉ chặn được đúng ví dụ được viết
ra để test.

---

## 4. Kết hợp 2+3: một file vừa có lỗ hổng High thật, vừa lộ secret — vẫn "All checks passed"

**Thực nghiệm kết hợp** — tạo file chứa cả API key thật (đặt tên `api_key` snake_case)
và một lỗi bảo mật High/High (`telnetlib`), rồi chạy đúng `pre-commit` này trên file đó:

```python
import telnetlib
api_key = "sk_live_51H8xJ2eZvKYlo2C0"
t = telnetlib.Telnet("internal-server.local")
```

```
$ git add sample2.py
$ python pre-commit
GitSecure: All checks passed.
$ echo $?
0
```

Trong khi chạy Bandit độc lập trên đúng thư mục đó:

```
$ bandit -r .
   Severity: High   Confidence: High
   Severity: High   Confidence: High
```

**Commit vẫn được cho qua** dù chứa 2 lỗ hổng High thật + 1 API key lộ rõ ràng — vì
lỗi 2 và 3 cộng dồn: naming né được regex, và bandit-check thì vô dụng do lỗi 2.

---

## 5. `scan_sensitive()` đọc **working tree**, không đọc **nội dung đã stage**

```python
with open(file_path, "r", errors="ignore") as f:
    content = f.read()
```

`open()` luôn đọc file **trên đĩa (working tree)** tại thời điểm hook chạy — không phải
nội dung **đã `git add` vào index**, là thứ thật sự sẽ được commit. Hai thứ này có thể
khác nhau.

**Bằng chứng:**

```
$ echo 'password = "123456"' > secret.py
$ git add secret.py                       # secret được STAGE vào index
$ echo 'x = 1  # da xoa secret o working tree' > secret.py   # sua file SAU KHI add, KHONG add lai

$ git show :secret.py        # noi dung SE duoc commit that su
password = "123456"

$ cat secret.py              # noi dung tren dia - noi hook doc bang open()
x = 1  # da xoa secret o working tree
```

Nếu chạy hook lúc này, `scan_sensitive()` đọc `secret.py` trên đĩa (đã sạch), **hoàn
toàn không thấy được `password = "123456"` vẫn đang nằm trong index và sắp được
commit**. Cách quét đúng phải dùng `git show :<file>` (đọc nội dung trong index) thay
vì `open(file_path)` (đọc trên đĩa).

---

## 6. Bản chất của pre-commit hook: chỉ là "hàng rào tự nguyện" phía client

Đây là giới hạn **kiến trúc**, không phải bug trong code, nhưng là điều quan trọng
nhất cần trình bày:

- `git commit --no-verify` bỏ qua **toàn bộ** pre-commit hook — không cần sửa code,
  không cần khai thác gì cả, chỉ cần gõ thêm một flag.
- Hook chỉ hoạt động nếu người dùng tự chạy `git config core.hooksPath .githooks` sau
  khi clone. Ai đó clone repo về mà quên bước này (hoặc cố tình bỏ qua) thì hook **im
  lặng không chạy** — không có cảnh báo, không có lỗi.
- `.githooks/pre-commit` nằm ngay trong repo, ai cũng đọc/sửa được — không có gì ngăn
  một lập trình viên tự sửa hoặc xoá điều kiện chặn trong chính file này rồi commit.

→ Kết luận: GitSecure là một **local dev convenience**, không phải một **security
control** thực sự. Muốn có control thực thi bắt buộc, phải đưa kiểm tra này lên
**server-side (pre-receive hook / CI pipeline / branch protection)** — nơi người commit
không tự tắt được.

---

## 7. `check_permissions()` trên Windows: "sửa" bằng cách tắt hẳn kiểm tra

```python
def check_permissions(file_path):
    if platform.system() == "Windows":
        return False
    ...
```

Bản gốc (không có dòng `if platform.system()`) chấm **mọi file trên Windows** là
world-writable — như log demo gốc cho thấy: 4/4 file bị báo "world-writable!" dù không
ai chỉnh quyền gì (do Windows không dùng bit quyền POSIX `S_IWOTH` theo cùng cách
Unix). Bản vá trong sách **không sửa cách kiểm tra cho đúng trên Windows — mà tắt hẳn
kiểm tra này khi chạy Windows**. Hệ quả: trên chính hệ điều hành nhiều sinh viên dùng
để làm bài, control "kiểm tra quyền truy cập file" **không bao giờ chạy, vĩnh viễn trả
`False`**, dù file thật sự bị `chmod 777` (qua WSL, Git Bash, hay khi kéo từ hệ thống
Linux khác vào).

---

## 8. Log injection ngay trong công cụ dạy chống log injection

```python
def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")
```

`msg` chứa trực tiếp đường dẫn file và pattern regex, được ghi thẳng vào
`gitsecure.log` mà không escape/lọc ký tự đặc biệt — trong khi mục **1.5.3 Phòng chống
chèn mã vào nhật ký** ngay bên dưới trong cùng tài liệu lại dạy nguyên tắc ngược lại:
*"Lọc và mã hoá dữ liệu đầu vào trước khi ghi log, loại bỏ ký tự đặc biệt"*. Nếu tên
file trong repo được đặt cố ý (ví dụ chứa chuỗi giả dạng một dòng log khác), nội dung
`gitsecure.log` có thể bị thao túng để đánh lừa người xem log sau này (log forging).

---

## 9. Bảng tổng hợp

| Thành phần | Mục tiêu quảng cáo | Thực tế | Mức độ |
|---|---|---|---|
| `run_bandit()` | Chặn commit nếu Bandit tìm thấy lỗi High | So sánh sai case (`SEVERITY:` vs `Severity:`) → **không bao giờ chặn** | **Nghiêm trọng** |
| `scan_sensitive()` | Phát hiện API key/secret/password/token hardcode | Bỏ lọt snake_case, giá trị không quote, JWT có dấu chấm, cú pháp YAML | **Cao** |
| Nguồn đọc file khi scan | Quét nội dung sắp được commit | Đọc working tree qua `open()`, không đọc index (`git show :file`) | Trung bình |
| Kiến trúc hook | "Tự động ngăn chặn rủi ro bảo mật" | Chỉ opt-in phía client, bị vô hiệu hoàn toàn bởi `--no-verify` hoặc quên cấu hình | **Cao** (kiến trúc) |
| `check_permissions()` trên Windows | Cảnh báo file world-writable | Luôn `return False` — vô hiệu hoá hoàn toàn trên Windows | Trung bình |
| `log()` | Ghi log phục vụ điều tra | Ghi thẳng dữ liệu chưa lọc, ngược nguyên tắc chống log injection | Thấp |

## 10. Bài học chính để trình bày

1. **Một security tool tự xưng "an toàn" vẫn cần bị kiểm chứng bằng thực nghiệm** —
   giống hệt bài học ở Lab1 với `sanitize_sql_input`. Ở đây thậm chí lỗi nằm ở một
   *typo case-sensitive đơn giản* (`SEVERITY` vs `Severity`) nhưng vô hiệu hoá hoàn
   toàn một trong ba lớp bảo vệ mà không hề có dấu hiệu gì (không exception, không log
   lỗi) — nên luôn cần test bằng case dương tính (input phải bị chặn) chứ không chỉ
   test bằng case "chạy không lỗi".
2. **Regex/blacklist theo mẫu cố định luôn có khoảng trống** — chỉ cần lệch style đặt
   tên biến hoặc định dạng giá trị so với ví dụ được viết ra để test.
3. **Pre-commit hook là công cụ hỗ trợ nhà phát triển, không phải security boundary.**
   Nó dễ bị tắt (`--no-verify`), dễ bị quên cấu hình, và không bảo vệ được gì nếu kẻ
   tấn công có quyền sửa chính repo. Kiểm soát thật sự phải nằm ở server (CI/CD gate,
   pre-receive hook, secret scanning của nhà cung cấp Git).
4. **"Vá lỗi" bằng cách tắt hẳn tính năng (`check_permissions` trên Windows) không phải
   là sửa lỗi** — nó chỉ chuyển từ "báo sai" (false positive) sang "không bao giờ báo"
   (false negative vĩnh viễn) trên nền tảng đó.

---

*Ghi chú: `pre-commit` được chép lại nguyên văn từ tài liệu thực hành, bao gồm cả bản
vá `check_permissions()` cho Windows ở trang 25 (bản dùng trong "Kết quả cuối cùng").
Theo tài liệu gốc, file này phải đặt tại `.githooks/pre-commit` (kèm
`git config core.hooksPath .githooks` và `chmod +x .githooks/pre-commit`) để thật sự
hoạt động như một Git hook — ở đây đặt phẳng ngay trong `Lab2/` để nhất quán với cách
trình bày ở Lab1. `bad_example.py` tương ứng với file `pre-commit-hook-test/bad.py`
trong tài liệu gốc. Toàn bộ payload/kết quả PoC ở trên đều là output thật khi chạy
`pre-commit` này (không sửa đổi) cùng Bandit 1.9.4, không phải suy đoán.*
