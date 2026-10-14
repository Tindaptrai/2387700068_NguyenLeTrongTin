from flask import Flask, render_template, request
from main import scan
from report.report_generator import ReportGenerator

app=Flask(__name__)
@app.get("/")
def index(): return render_template("index.html")
@app.post("/scan")
def run_scan():
    url=request.form.get("url","").strip()
    try:
        findings=scan(url)
        return render_template("result.html",url=url,findings=findings,report=ReportGenerator().generate(findings))
    except ValueError as exc:
        return render_template("result.html",url=url,findings=[],report=str(exc)),400
if __name__=="__main__": app.run(host="127.0.0.1",port=5001,debug=False)
