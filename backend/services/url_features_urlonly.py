import re
import math
import tldextract

def url_entropy(url: str):
    prob = [float(url.count(c)) / len(url) for c in set(url)]
    return - sum([p * math.log(p) / math.log(2) for p in prob])

def extract_url_only_features(url: str):
    features = {}
    u = url.strip()

    ext = tldextract.extract(u)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain

    features["domain"] = domain
    features["subdomain_count"] = len(subdomain.split(".")) if subdomain else 0
    features["url_length"] = len(u)
    features["num_digits"] = sum(c.isdigit() for c in u)
    features["num_special_chars"] = sum(c in "@!%*{}[]$&" for c in u)
    features["num_params"] = u.count("&") + u.count("?")
    features["has_ip"] = 1 if re.match(r"https?://(?:\d{1,3}\.){3}\d{1,3}", u) else 0
    features["entropy"] = url_entropy(u) if len(u) > 0 else 0
    features["is_https"] = 1 if u.startswith("https") else 0

    bad_tlds = ["zip", "xyz", "click", "work", "rest", "country", "kim", "ml", "ga", "cf", "gq"]
    features["bad_tld"] = 1 if ext.suffix in bad_tlds else 0

    features["suspicious_at"] = 1 if "@" in u else 0
    features["long_hostname"] = 1 if len(ext.subdomain or "") > 20 else 0

    return features

