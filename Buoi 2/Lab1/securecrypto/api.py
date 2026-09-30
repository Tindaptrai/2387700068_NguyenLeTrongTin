from flask import Flask, request, jsonify
from securecrypto import aes_utils
import os


app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "upload")
os.makedirs(FILES_DIR, exist_ok=True)


@app.route("/encrypt", methods=["POST"])
def encrypt():
    f = request.files["file"]
    password = request.form["password"]
    save_path = os.path.join(FILES_DIR, f.filename)
    f.save(save_path)
    key = aes_utils.encrypt_file_aes(save_path, password)
    return jsonify({"key": key})


@app.route("/decrypt", methods=["POST"])
def decrypt():
    f = request.files["file"]
    password = request.form["password"]
    save_path = os.path.join(FILES_DIR, f.filename)
    f.save(save_path)
    out_path = aes_utils.decrypt_file_aes(save_path, password)
    return jsonify({"output": out_path})


if __name__ == "__main__":
    app.run()
