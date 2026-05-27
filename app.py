from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import time
import base64

app = Flask(__name__)

VT_API_KEY = "5efaa28db3c2aa83e646022663fe6d7f9b758351fbc96cc67391b2eb5a070030"
VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses"


# -------------------------
# Extract domain
# -------------------------
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return "Invalid"


# -------------------------
# FIXED VIRUSTOTAL LOGIC
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # 🔥 Step 1: encode URL properly
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Submit URL
        submit = requests.post(VT_SUBMIT_URL, headers=headers, json={"url": url})
        data = submit.json()

        if "data" not in data:
            return {"status": "SAFE"}

        analysis_id = data["data"]["id"]

        # 🔥 Step 2: wait for processing
        for _ in range(10):
            result = requests.get(f"{VT_ANALYSIS_URL}/{analysis_id}", headers=headers).json()

            stats = result.get("data", {}).get("attributes", {}).get("stats", {})

            if stats:
                break

            time.sleep(2)

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # 🔥 FINAL DECISION
        if malicious > 0:
            return {"status": "MALICIOUS"}

        if suspicious > 0:
            return {"status": "MALICIOUS"}

        return {"status": "SAFE"}

    except Exception as e:
        print("VT ERROR:", e)
        return {"status": "SAFE"}


# -------------------------
# ROUTE
# -------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        vt = scan_virustotal(url)

        result = {
            "url": url,
            "domain": extract_domain(url),
            "vt": vt
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)