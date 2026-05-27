from flask import Flask, render_template, request
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/urls"


# -------------------------
# Extract domain
# -------------------------
def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return "Invalid URL"


# -------------------------
# Domain age (SAFE)
# -------------------------
def get_domain_age(domain):
    try:
        import whois

        data = whois.whois(domain)
        creation = data.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return "Unknown"

        return (datetime.now() - creation).days

    except Exception as e:
        print("WHOIS ERROR:", e)
        return "Unknown"


# -------------------------
# VirusTotal (SAFE VERSION)
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        response = requests.post(VT_URL, headers=headers, data={"url": url})
        result = response.json()

        if "data" not in result:
            return {"error": "VT failed"}

        analysis_id = result["data"]["id"]

        fetch_url = f"{VT_URL}/{analysis_id}"
        analysis = requests.get(fetch_url, headers=headers).json()

        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})

        malicious = stats.get("malicious", 0)

        return {
            "status": "MALICIOUS" if malicious > 0 else "SAFE",
            "stats": stats
        }

    except Exception as e:
        print("VT ERROR:", e)
        return {"status": "ERROR", "stats": {}}


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


# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)