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
        return "Invalid URL"


# -------------------------
# VirusTotal Scan (FIXED)
# -------------------------
def scan_virustotal(url):
    try:
        headers = {"x-apikey": VT_API_KEY}

        # encode URL correctly
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Submit URL for scanning
        requests.post(VT_SUBMIT_URL, headers=headers, json={"url": url})

        # Wait + fetch final result from URL report
        for _ in range(10):
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )

            data = response.json()

            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            if stats:
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)

                if malicious > 0:
                    return {"status": "MALICIOUS"}

                if suspicious > 0:
                    return {"status": "SUSPICIOUS"}

                return {"status": "SAFE"}

            time.sleep(2)

        return {"status": "UNKNOWN"}

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

        vt_result = scan_virustotal(url)

        result = {
            "url": url,
            "domain": extract_domain(url),
            "vt": vt_result
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)