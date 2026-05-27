from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import time

app = Flask(__name__)

VT_API_KEY = "5efaa28db3c2aa83e646022663fe6d7f9b758351fbc96cc67391b2eb5a070030"
VT_URL = "https://www.virustotal.com/api/v3/urls"


# -------------------------
# Domain extraction
# -------------------------
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return "Invalid"


# -------------------------
# SAFE VirusTotal (BINARY RESULT ONLY)
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # Step 1: submit URL
        submit = requests.post(VT_URL, headers=headers, data={"url": url})
        data = submit.json()

        if "data" not in data:
            return {"status": "SAFE"}  # fallback safe

        analysis_id = data["data"]["id"]

        result_url = f"{VT_URL}/{analysis_id}"

        stats = {}

        # wait for analysis (important)
        for _ in range(5):
            result = requests.get(result_url, headers=headers).json()
            stats = result.get("data", {}).get("attributes", {}).get("stats", {})

            if stats:
                break

            time.sleep(2)

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # -------------------------
        # FINAL BINARY DECISION
        # -------------------------
        if malicious > 0 or suspicious > 0:
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