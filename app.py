from flask import Flask, request, render_template
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

VT_API_KEY = "5efaa28db3c2aa83e646022663fe6d7f9b758351fbc96cc67391b2eb5a070030"
VT_URL = "https://www.virustotal.com/api/v3/urls"


def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc


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

    except:
        return "Unknown"


def scan_with_virustotal(url): 
    try:
        headers = {"x-apikey": VT_API_KEY}
        encoded_url = requests.utils.quote(url, safe="")

        # Submit URL
        submit_resp = requests.post(VT_URL, headers=headers, data={"url": url})

        if submit_resp.status_code != 200:
            return {"error": "VirusTotal Submission Failed"}

        analysis_id = submit_resp.json()["data"]["id"]

        # Get Results
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result_resp = requests.get(result_url, headers=headers)
        result_data = result_resp.json()

        return result_data["data"]["attributes"]["stats"]

    except Exception as e:
        return {"error": str(e)}


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        url = request.form["url"]
        domain = extract_domain(url)
        age = get_domain_age(domain)
        vt = scan_with_virustotal(url)

        result = {
            "url": url,
            "domain": domain,
            "age": age,
            "vt": vt
        }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)