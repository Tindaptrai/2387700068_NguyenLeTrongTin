"""Mẫu cố ý không an toàn để SAST phân tích; không chạy file này."""

password = "LAB_ONLY_CHANGE_ME"  # Mật khẩu giả để thử dò hard-coded secret.
import pickle


def unsafe_func(data):
    return eval(data)  # Mẫu nguy hiểm: eval.


def safe_func():
    print("Hello world")
