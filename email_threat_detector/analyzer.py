"""
Email Threat & Scam Detection engine (SIH26106-style project).

Pipeline:  parse -> header analysis -> content ML -> URL analysis
           -> attachment analysis -> route/geolocation -> risk score + report
"""
import difflib
import hashlib
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse

from dataset import LEGIT, SCAM

# ----------------------------------------------------------------- constants
BRANDS = {
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "paypal": "paypal.com", "amazon": "amazon.in", "google": "google.com",
    "microsoft": "microsoft.com", "paytm": "paytm.com", "phonepe": "phonepe.com",
    "flipkart": "flipkart.com", "irctc": "irctc.co.in", "netflix": "netflix.com",
}
SUSPICIOUS_TLDS = {"xyz", "top", "click", "zip", "tk", "ml", "gq", "cf", "work", "support", "loan", "rest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at"}
RISKY_EXT = {"exe", "js", "vbs", "scr", "bat", "cmd", "jar", "iso", "lnk", "msi", "ps1", "hta", "docm", "xlsm"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}
SCAM_PHRASES = [  # (regex, explanation)
    (r"\botp\b|\bcvv\b|\bpin\b", "asks for OTP / PIN / CVV"),
    (r"urgent|immediately|within \d+ hours|abhi|turant|final warning|last chance", "creates urgency"),
    (r"kyc|account (has been )?(blocked|suspended|locked|limited)|band ho", "account-block / KYC threat"),
    (r"lottery|won |winner|prize|inaam|lakh", "prize / lottery lure"),
    (r"gift card|wire transfer|processing fee|registration fee|insurance fee|customs fee", "unusual payment request"),
    (r"password|login|verify your", "credential harvesting wording"),
]
PRIVATE_NET = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


# ------------------------------------------------------------- content model
_MODEL = None


def _get_model():
    """Train a TF-IDF + Logistic Regression model on first use (takes <1s)."""
    global _MODEL
    if _MODEL is None:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression

        texts = SCAM + LEGIT
        labels = [1] * len(SCAM) + [0] * len(LEGIT)
        vec = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, sublinear_tf=True, min_df=1)
        X = vec.fit_transform(texts)
        clf = LogisticRegression(C=5, max_iter=1000).fit(X, labels)
        _MODEL = (vec, clf)
    return _MODEL


def content_score(text):
    """Return (scam probability, top contributing words) - explainable via LR coefficients."""
    vec, clf = _get_model()
    X = vec.transform([text])
    prob = float(clf.predict_proba(X)[0][1])
    names = vec.get_feature_names_out()
    contrib = X.toarray()[0] * clf.coef_[0]
    top = [(names[i], round(float(contrib[i]), 3)) for i in contrib.argsort()[::-1][:6] if contrib[i] > 0]
    return prob, top


# -------------------------------------------------------------------- parse
def parse_email(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body_plain, body_html = "", ""
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        ctype = part.get_content_type()
        if fname:
            data = part.get_payload(decode=True) or b""
            attachments.append({"filename": fname, "content_type": ctype, "data": data})
        elif ctype == "text/plain":
            body_plain += part.get_content()
        elif ctype == "text/html":
            body_html += part.get_content()
    html_text = re.sub(r"<[^>]+>", " ", body_html)
    return msg, (body_plain or html_text), body_html, attachments


def domain_of(addr):
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""


def registrable(domain):
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "ac", "net"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ------------------------------------------------------------------ headers
def analyze_headers(msg):
    findings, score = [], 0
    disp, from_addr = parseaddr(str(msg["From"] or ""))
    _, reply_to = parseaddr(str(msg["Reply-To"] or ""))
    _, return_path = parseaddr(str(msg["Return-Path"] or ""))
    from_dom = domain_of(from_addr)

    auth = str(msg["Authentication-Results"] or "").lower() + str(msg["Received-SPF"] or "").lower()
    if not auth.strip():
        findings.append(("medium", "No SPF/DKIM/DMARC results present in headers")); score += 6
    else:
        for chk in ("spf", "dkim", "dmarc"):
            if f"{chk}=pass" in auth or (chk == "spf" and auth.startswith("pass")):
                continue
            if f"{chk}=fail" in auth or f"{chk}=softfail" in auth or f"{chk}=none" in auth:
                findings.append(("high", f"{chk.upper()} check failed - sender may be spoofed")); score += 10

    if reply_to and domain_of(reply_to) != from_dom:
        findings.append(("high", f"Reply-To domain ({domain_of(reply_to)}) differs from From domain ({from_dom})")); score += 10
    if return_path and domain_of(return_path) and domain_of(return_path) != from_dom:
        findings.append(("medium", f"Return-Path domain ({domain_of(return_path)}) differs from From domain")); score += 5

    low = normalize_leet(f"{disp} {from_dom}".lower())
    for brand, official in BRANDS.items():
        if brand in low and registrable(from_dom) != official:
            findings.append(("high", f"Sender claims to be '{brand.upper()}' but domain is '{from_dom}' (official: {official})")); score += 12
            break
    if from_dom.split(".")[-1] in SUSPICIOUS_TLDS:
        findings.append(("medium", f"Sender uses a high-risk TLD (.{from_dom.split('.')[-1]})")); score += 5
    return min(score, 30), findings


# ------------------------------------------------------------------ content
def analyze_content(subject, body):
    text = f"{subject}\n{body}"
    prob, top = content_score(text)
    findings = []
    for pattern, why in SCAM_PHRASES:
        if re.search(pattern, text, re.I):
            findings.append(("medium", f"Scam pattern: {why}"))
    rule_bonus = min(len(findings) * 0.05, 0.2)
    final = min(prob + rule_bonus, 1.0)
    return final, prob, top, findings


# --------------------------------------------------------------------- URLs
def normalize_leet(s):
    return s.replace("1", "l").replace("0", "o").replace("3", "e").replace("5", "s").replace("rn", "m")


def analyze_urls(body_plain, body_html):
    urls = set(re.findall(r"https?://[^\s<>\"')]+", body_plain + " " + body_html))
    mismatches = []
    for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', body_html, re.S | re.I):
        label = re.sub(r"<[^>]+>", "", label).strip()
        m = re.search(r"([a-z0-9-]+\.)+[a-z]{2,}", label.lower())
        if m and domain_of("x@" + (urlparse(href).hostname or "")) != m.group(0) and m.group(0) not in (urlparse(href).hostname or ""):
            mismatches.append((label, href))

    results, score = [], 0
    for u in sorted(urls):
        host = (urlparse(u).hostname or "").lower()
        flags = []
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append("IP address instead of domain")
        if host in SHORTENERS:
            flags.append("URL shortener hides destination")
        if host.split(".")[-1] in SUSPICIOUS_TLDS:
            flags.append(f"High-risk TLD .{host.split('.')[-1]}")
        if host.count(".") >= 4:
            flags.append("Too many subdomains")
        if "@" in u or u.startswith("http://"):
            flags.append("Insecure / obfuscated URL")
        label = normalize_leet(registrable(host).split(".")[0])
        for brand, official in BRANDS.items():
            if registrable(host) == official:
                break
            if (brand in label and label != brand) or (
                difflib.SequenceMatcher(None, label, brand).ratio() > 0.8 and label != brand
            ) or (brand in host and registrable(host) != official):
                flags.append(f"Looks like a fake '{brand}' domain (lookalike)")
                break
        results.append({"url": u, "host": host, "flags": flags})
        score += 6 * len(flags)
    for label, href in mismatches:
        score += 8
    return min(score, 25), results, mismatches


# -------------------------------------------------------------- attachments
def analyze_attachments(attachments):
    out, score = [], 0
    for a in attachments:
        name = a["filename"].lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        flags = []
        if ext in RISKY_EXT:
            flags.append(f"Risky file type (.{ext})"); score += 8
        if len(parts) > 2 and parts[-2] in DOC_EXT and ext in RISKY_EXT:
            flags.append("Double extension trick (looks like a document)"); score += 6
        if ext in ("docm", "xlsm"):
            flags.append("Macro-enabled Office file")
        out.append({
            "filename": a["filename"], "size": len(a["data"]),
            "sha256": hashlib.sha256(a["data"]).hexdigest(), "flags": flags,
        })
    return min(score, 15), out


# ------------------------------------------------------- route / geolocation
def analyze_route(msg):
    """Extract public IPs from Received headers (oldest hop first).
    Geolocation uses a MaxMind GeoLite2-City.mmdb in ./data if present."""
    hops = []
    for h in reversed(msg.get_all("Received") or []):
        for ip in re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", str(h)):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            private = any(addr in n for n in PRIVATE_NET)
            hops.append({"ip": ip, "private": private, **_geo(ip, private)})
    seen, uniq = set(), []
    for h in hops:
        if h["ip"] not in seen:
            seen.add(h["ip"]); uniq.append(h)
    return uniq


def _geo(ip, private):
    if private:
        return {"country": "Private network", "city": "", "lat": None, "lon": None}
    try:
        import geoip2.database
        with geoip2.database.Reader("data/GeoLite2-City.mmdb") as r:
            x = r.city(ip)
            return {"country": x.country.name or "?", "city": x.city.name or "",
                    "lat": x.location.latitude, "lon": x.location.longitude}
    except Exception:
        return {"country": "Unknown (add GeoLite2 DB)", "city": "", "lat": None, "lon": None}


# -------------------------------------------------------------------- main
def analyze(raw: bytes):
    msg, body, html, atts = parse_email(raw)
    subject = str(msg["Subject"] or "")

    h_score, h_find = analyze_headers(msg)
    c_prob, ml_prob, top_words, c_find = analyze_content(subject, body)
    u_score, urls, mismatches = analyze_urls(body, html)
    a_score, att_info = analyze_attachments(atts)
    route = analyze_route(msg)

    content_pts = round(c_prob * 35)
    total = min(h_score + content_pts + u_score + a_score, 100)
    verdict = "MALICIOUS / PHISHING" if total >= 60 else "SUSPICIOUS" if total >= 30 else "LIKELY SAFE"

    reasons = []
    reasons += [f"[HEADER] {m}" for _, m in h_find]
    if c_prob >= 0.5:
        reasons.append(f"[CONTENT] ML model rates text as scam-like ({ml_prob:.0%})")
    reasons += [f"[CONTENT] {m}" for _, m in c_find]
    for u in urls:
        reasons += [f"[URL] {u['host']}: {f}" for f in u["flags"]]
    reasons += [f"[URL] Link text '{l}' points to a different site: {h}" for l, h in mismatches]
    for a in att_info:
        reasons += [f"[ATTACHMENT] {a['filename']}: {f}" for f in a["flags"]]

    return {
        "verdict": verdict, "risk_score": total,
        "breakdown": {"header": h_score, "content": content_pts, "url": u_score, "attachment": a_score},
        "from": str(msg["From"] or ""), "subject": subject, "date": str(msg["Date"] or ""),
        "reasons": reasons, "ml_probability": round(ml_prob, 3), "top_words": top_words,
        "urls": urls, "attachments": att_info, "route": route,
    }


def report_text(r):
    lines = [
        "=" * 60, "EMAIL FORENSIC REPORT", "=" * 60,
        f"From    : {r['from']}", f"Subject : {r['subject']}", f"Date    : {r['date']}", "",
        f"VERDICT : {r['verdict']}  (risk {r['risk_score']}/100)",
        "Breakdown: " + ", ".join(f"{k}={v}" for k, v in r["breakdown"].items()), "",
        "Why:",
    ] + [f"  - {x}" for x in r["reasons"]] + ["", "Route (oldest hop first):"]
    lines += [f"  {i+1}. {h['ip']}  {h['country']} {h['city']}" for i, h in enumerate(r["route"])] or ["  (no hops found)"]
    lines += ["", "Attachments:"] + [f"  {a['filename']}  sha256={a['sha256'][:16]}..." for a in r["attachments"]] if r["attachments"] else []
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    for path in sys.argv[1:]:
        res = analyze(open(path, "rb").read())
        print(report_text(res), "\n")
