from flask import Flask, render_template, request
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

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
# WHOIS (safe)
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
# FIXED VirusTotal Logic (IMPORTANT)
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # Step 1: Submit URL
        submit = requests.post(VT_URL, headers=headers, data={"url": url})
        data = submit.json()

        if "data" not in data:
            return {"status": "ERROR", "score": 0}

        analysis_id = data["data"]["id"]

        # Step 2: Get results
        result_url = f"{VT_URL}/{analysis_id}"
        result = requests.get(result_url, headers=headers).json()

        stats = result.get("data", {}).get("attributes", {}).get("stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total = sum(stats.values()) if stats else 0

        # 🔥 REAL DECISION LOGIC
        if malicious > 0:
            status = "MALICIOUS"
            score = 100
        elif suspicious > 0:
            status = "SUSPICIOUS"
            score = 60
        elif total == 0:
            status = "UNKNOWN"
            score = 50
        else:
            status = "SAFE"
            score = 10

        return {
            "status": status,
            "score": score,
            "stats": stats
        }

    except Exception as e:
        print("VT ERROR:", e)
        return {"status": "ERROR", "score": 0, "stats": {}}


# -------------------------
# Route
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