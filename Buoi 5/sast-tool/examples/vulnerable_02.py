"""Mẫu cố ý không an toàn để SAST phân tích; không chạy file này."""


def dangerous_eval(user_input):
    return eval(user_input)


def read_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()


def execute_code(code):
    exec(code)
