# app.py
from flask import Flask, request, render_template
from scanner import WebSecurityScanner
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    scanner = WebSecurityScanner(url)
    vulns = scanner.scan()
    return render_template("results.html", results=vulns, url=url)

if __name__ == "__main__":
    if not os.path.exists("reports"):
        os.makedirs("reports")
    app.run(debug=True)
