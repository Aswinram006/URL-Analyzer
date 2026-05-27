from flask import Flask, render_template, request
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

VT_API_KEY = "YOUR_API_KEY_HERE"
VT_URL = "https://www.virustotal.com/api/v3/urls"

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age_days = (datetime.now() - creation).days
        return age_days
    except:
        return "Unknown"

def virustotal_scan(url):
    headers = {"x-apikey": VT_API_KEY}

    # URL encode + scan request
    resp = requests.post(VT_URL, headers=headers, data={"url": url})
    if resp.status_code != 200:
        return "Error scanning"

    scan_id = resp.json()["data"]["id"]

    # Fetch results
    analysis_url = f"{VT_URL}/{scan_id}"
    result = requests.get(analysis_url, headers=headers).json()

    stats = result["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)

    return "Malicious" if malicious > 0 else "Safe"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form["url"]
        domain = extract_domain(url)
        age = get_domain_age(domain)
        vt = virustotal_scan(url)

        result = {
            "url": url,
            "domain": domain,
            "age": age,
            "vt": vt
        }

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
