from flask import Flask, render_template, request

from core import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input,
)

app = Flask(__name__, template_folder=".")


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    if request.method == "POST":
        results = {
            "email": validate_email(request.form.get("email", "")),
            "url": validate_url(request.form.get("url", "")),
            "filename": validate_filename(request.form.get("filename", "")),
            "sql": sanitize_sql_input(request.form.get("sql", "")),
            "html": sanitize_html_input(request.form.get("html", "")),
        }
    return render_template("index.html", results=results)


if __name__ == "__main__":
    app.run(debug=True)
