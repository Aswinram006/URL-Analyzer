from flask import Flask, render_template, request
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse
import time

app = Flask(__name__)

VT_API_KEY = "5efaa28db3c2aa83e646022663fe6d7f9b758351fbc96cc67391b2eb5a070030"
VT_URL = "https://www.virustotal.com/api/v3/urls"


# -------------------------
# Extract domain
# -------------------------
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return "Invalid"


# -------------------------
# WHOIS
# -------------------------
def get_domain_age(domain):
    try:
        import whois

        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return "Unknown"

        return (datetime.now() - creation).days

    except:
        return "Unknown"


# -------------------------
# FIXED VIRUSTOTAL (WITH WAIT + RETRY)
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # STEP 1: Submit URL
        submit = requests.post(VT_URL, headers=headers, data={"url": url})
        data = submit.json()

        if "data" not in data:
            return {"status": "ERROR", "score": 0}

        analysis_id = data["data"]["id"]

        # STEP 2: WAIT FOR ANALYSIS (IMPORTANT FIX)
        analysis_url = f"{VT_URL}/{analysis_id}"

        stats = None

        # retry 5 times (VirusTotal delay fix)
        for i in range(5):
            result = requests.get(analysis_url, headers=headers).json()
            stats = result.get("data", {}).get("attributes", {}).get("stats", {})

            if stats:
                break

            time.sleep(2)  # wait for VT processing

        if not stats:
            return {"status": "UNKNOWN", "score": 50}

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        # -------------------------
        # FINAL DECISION LOGIC
        # -------------------------
        if malicious > 0:
            return {"status": "MALICIOUS", "score": 100}

        elif suspicious > 0:
            return {"status": "SUSPICIOUS", "score": 60}

        elif harmless > 0:
            return {"status": "SAFE", "score": 10}

        else:
            return {"status": "UNKNOWN", "score": 50}

    except Exception as e:
        print("VT ERROR:", e)
        return {"status": "ERROR", "score": 0}


# -------------------------
# ROUTE
# -------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form.get("url")

        domain = extract_domain(url)
        age = get_domain_age(domain)
        vt = scan_virustotal(url)

        result = {
            "url": url,
            "domain": domain,
            "age": age,
            "vt": vt
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)