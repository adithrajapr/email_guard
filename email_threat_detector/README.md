# 🛡️ AI Email Threat & Scam Detector
Based on **SIH26106 – AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform** (AICTE Cyber Security Cell, theme: Blockchain & Cybersecurity).

## What it does
Upload an `.eml` file and get a **risk score (0-100)**, a **verdict**, a plain-English list of **reasons**, and a downloadable **forensic report**.

| Module | Technique |
|---|---|
| Header forensics | SPF/DKIM/DMARC results, Reply-To / Return-Path mismatch, brand impersonation (incl. `amaz0n`-style lookalikes), risky TLDs |
| Scam detection (ML) | TF-IDF + Logistic Regression, English + Hinglish samples, explainable top words, plus rule patterns (OTP, KYC, lottery, urgency) |
| URL analysis | Shorteners, IP URLs, lookalike domains, risky TLDs, link-text vs real-href mismatch |
| Attachments | SHA-256 hashing, risky extensions, double-extension trick, macro files |
| Route / geolocation | Extracts IPs from `Received` headers; maps them with MaxMind GeoLite2 (optional) |
| Risk scorer | Header (max 30) + Content (max 35) + URL (max 25) + Attachment (max 15), capped at 100 |

## Run it
```bash
pip install -r requirements.txt
python make_samples.py                 # creates safe synthetic test emails
python analyzer.py samples/*.eml       # command-line forensic reports
python evaluate.py                     # cross-validated model metrics
streamlit run app.py                   # web dashboard
```
Optional: download `GeoLite2-City.mmdb` (free MaxMind account) into `data/` to enable the map.

## Architecture
```
.eml -> parser -> [header | content ML | URL | attachment | route] -> risk scorer -> dashboard + report
```

## Results (demo dataset, 5-fold CV)
Accuracy ~93% on 56 labelled messages (see `evaluate.py`). This is a small demo set; the real model should be trained on SpamAssassin, Enron, Nazario and Kaggle phishing datasets.

## Limitations & future work
- Small training set; no deep model yet (next: fine-tune DistilBERT / multilingual BERT).
- Geolocation shows the *relay* location; VPNs and webmail can hide the true origin.
- Add live reputation checks (VirusTotal, Google Safe Browsing, PhishTank) and WHOIS domain-age.
- Add IMAP inbox integration and a case-management database for investigators.
- Privacy: emails are processed locally and not stored.

## Safety
All sample emails are synthetic and harmless. Never open real phishing attachments outside an isolated VM.

## Team
_Add names / roll numbers here._
