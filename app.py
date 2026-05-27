from flask import Flask, request, render_template
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# ⚠️ Keep your API key safe (better: use environment variable in Render later)
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/urls"


# ---------------------------
# Extract domain safely
# ---------------------------
def extract_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return "Invalid URL"


# ---------------------------
# Domain age checker (safe)
# ---------------------------
def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days

        return "Unknown"

    except Exception as e:
        print("WHOIS ERROR:", e)
        return "Unknown"


# ---------------------------
# VirusTotal scan (safe version)
# ---------------------------
def scan_with_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # Submit URL to VirusTotal
        submit_resp = requests.post(VT_URL, headers=headers, data={"url": url})

        if submit_resp.status_code != 200:
            return {"error": "VirusTotal submission failed"}

        submit_json = submit_resp.json()

        if "data" not in submit_json:
            return {"error": "Invalid VirusTotal response"}

        analysis_id = submit_json["data"]["id"]

        # Get analysis results
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_resp = requests.get(result_url, headers=headers)

        result_json = result_resp.json()

        stats = result_json.get("data", {}).get("attributes", {}).get("stats", {})

        return stats

    except Exception as e:
        print("VT ERROR:", e)
        return {"error": str(e)}


# ---------------------------
# Flask route
# ---------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url")

        if not url:
            error = "No URL provided"
            return render_template("index.html", result=None, error=error)

        domain = extract_domain(url)
        age = get_domain_age(domain)
        vt = scan_with_virustotal(url)

        result = {
            "url": url,
            "domain": domain,
            "age": age,
            "vt": vt
        }

    return render_template("index.html", result=result, error=error)


# ---------------------------
# Run locally
# ---------------------------
if __name__ == "__main__":
    app.run(debug=True)