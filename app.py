from flask import Flask, render_template, request
import requests
from urllib.parse import urlparse
import whois
from bs4 import BeautifulSoup
import datetime
import ssl
import socket
import webbrowser

app = Flask(__name__)

def check_ssl_cert(url):
    try:
        hostname = urlparse(url).netloc
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return True
    except:
        return False

def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.datetime.now() - creation_date).days
        return age
    except:
        return -1

def detect_phishing_patterns(html_text):
    score = 0
    if "login" in html_text.lower():
        score += 1
    if "password" in html_text.lower():
        score += 1
    if "bank" in html_text.lower():
        score += 1
    return score

def get_website_summary(url):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        title = soup.title.string if soup.title else "No Title Found"
        description = soup.find("meta", attrs={"name": "description"})
        desc = description["content"] if description else "No description"
        return title.strip(), desc.strip(), soup.text[:500]
    except:
        return "Unavailable", "Unable to fetch summary", ""

def analyze_link(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_age = get_domain_age(domain)
    ssl_ok = check_ssl_cert(url)
    title, desc, html_text = get_website_summary(url)
    phishing_score = detect_phishing_patterns(html_text)

    # Scoring logic
    score = 50
    if ssl_ok:
        score += 20
    if domain_age > 180:
        score += 20
    if phishing_score == 0:
        score += 10
    elif phishing_score >= 3:
        score -= 20

    is_safe = "Safe ✅" if score >= 70 else "Suspicious ⚠️"
    return {
        "domain": domain,
        "title": title,
        "desc": desc,
        "ssl_ok": ssl_ok,
        "domain_age": domain_age,
        "score": score,
        "status": is_safe,
        "url": url
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        if not url.startswith("http"):
            url = "http://" + url
        result = analyze_link(url)
        return render_template("index.html", result=result)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
