import re
import math
import requests
from bs4 import BeautifulSoup
import tldextract

def url_entropy(url):
    """Calculate Shannon entropy of URL."""
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return - sum([p * math.log(p) / math.log(2) for p in prob])

def extract_features(url: str):
    features = {}

    # Parse domain
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain
    features["domain"] = domain
    features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0

    # URL-based features
    features["url_length"] = len(url)
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_special_chars"] = sum(c in "@!%*{}[]$&" for c in url)
    features["num_params"] = url.count("&")
    features["has_ip"] = bool(re.match(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url))
    features["entropy"] = url_entropy(url)
    features["is_https"] = url.startswith("https")

    # Suspicious TLD check
    bad_tlds = ["zip", "xyz", "click", "work", "rest", "country", "kim", "ml", "ga", "cf", "gq"]
    features["bad_tld"] = 1 if ext.suffix in bad_tlds else 0

    # Fetch HTML
    try:
        response = requests.get(url, timeout=5)
        html = response.text
    except:
        html = ""

    soup = BeautifulSoup(html, "html.parser")

    # HTML-based features
    form_tags = soup.find_all("form")
    features["form_count"] = len(form_tags)

    features["password_fields"] = len(soup.find_all("input", {"type": "password"}))
    features["scripts_external"] = len([s for s in soup.find_all("script") if s.get("src")])
    features["images"] = len(soup.find_all("img"))
    features["hidden_inputs"] = len(soup.find_all("input", {"type": "hidden"}))

    # Only check keywords inside visible text, not entire HTML
    visible_text = soup.get_text(separator=" ").lower()

    keywords = [
        "verify your account",
        "login required",
        "password reset",
        "update your billing",
        "confirm your identity",
        "suspend",
        "security alert",
        "verify now"
    ]

    features["keyword_hits"] = sum(1 for k in keywords if k in visible_text)

    # Base64 detection
    features["has_base64"] = "base64" in html.lower()

    return features

