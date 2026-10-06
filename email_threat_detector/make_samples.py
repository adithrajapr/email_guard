"""Generates safe, synthetic .eml test files (no real malware)."""
from email.message import EmailMessage

def save(name, msg):
    open(f"samples/{name}.eml", "wb").write(msg.as_bytes())

# 1. Bank phishing
m = EmailMessage()
m["From"] = "SBI Support <alerts@sbi-secure-login.xyz>"
m["To"] = "student@example.com"
m["Reply-To"] = "claims@gmail-helpdesk.top"
m["Subject"] = "URGENT: Your SBI account is blocked - update KYC"
m["Date"] = "Mon, 05 Oct 2026 09:12:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=fail; dkim=none; dmarc=fail"
m["Received"] = "from mail.evil-host.xyz ([185.220.101.45]) by mx.example.com; Mon, 05 Oct 2026 09:12:00 +0000"
m["Received"] = "from relay.example.net ([10.0.0.5]) by mx.example.com; Mon, 05 Oct 2026 09:12:05 +0000"
m.set_content("Dear customer, your SBI account has been blocked. Update your KYC immediately and share the OTP within 24 hours.")
m.add_alternative('<p>Dear customer, your account is blocked. Verify password and OTP now: '
                  '<a href="http://sbi-secure-login.xyz/verify">www.onlinesbi.com</a> '
                  'or http://bit.ly/3xYzKyc</p>', subtype="html")
save("01_bank_phishing", m)

# 2. Hinglish lottery scam
m = EmailMessage()
m["From"] = "Lucky Draw <winner@prize-india.top>"
m["To"] = "student@example.com"
m["Subject"] = "Badhai ho! Aapne 25 lakh ka inaam jeeta hai"
m["Date"] = "Tue, 06 Oct 2026 07:00:00 +0000"
m["Received"] = "from smtp.prize-india.top ([103.21.58.10]) by mx.example.com"
m.set_content("Badhai ho! Aapne 25 lakh ka lottery jeeta hai. Claim karne ke liye processing fee bhejein aur apna account number aur OTP share karein. http://192.168.4.4.example-claim.click/win")
save("02_hinglish_lottery_scam", m)

# 3. Malicious invoice (synthetic bytes, harmless)
m = EmailMessage()
m["From"] = "Accounts <billing@amaz0n-invoices.work>"
m["To"] = "student@example.com"
m["Subject"] = "Invoice attached - open immediately"
m["Date"] = "Tue, 06 Oct 2026 08:00:00 +0000"
m["Authentication-Results"] = "mx.example.com; spf=softfail; dkim=none; dmarc=none"
m["Received"] = "from vps.amaz0n-invoices.work ([45.155.205.9]) by mx.example.com"
m.set_content("Please open the attached invoice and enable macros to view the payment details immediately.")
m.add_attachment(b"DUMMY-NOT-REAL-MALWARE", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
save("03_malicious_invoice", m)

# 4. Legitimate
m = EmailMessage()
m["From"] = "Prof. Rao <rao@college.ac.in>"
m["To"] = "student@example.com"
m["Subject"] = "Project review meeting tomorrow"
m["Date"] = "Mon, 05 Oct 2026 15:30:00 +0530"
m["Authentication-Results"] = "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
m["Received"] = "from mail.college.ac.in ([14.139.200.10]) by mx.example.com"
m.set_content("Hi team, attaching the agenda for tomorrow's project review at 10 AM. Please go through the slides before we meet.")
save("04_legit_meeting", m)
