import re
from urllib.parse import urlparse
import imaplib
import email

# Suspicious keywords often found in phishing emails
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "update", "login", "account", "password", "click here",
    "reset", "unauthorized", "suspend", "locked", "immediately", "confirm"
]

# Urgent phrases and poor grammar indicators
URGENT_LANGUAGE = ["act now", "immediately", "as soon as possible", "response required", "final notice"]
GRAMMAR_FLAGS = ["dear customer", "your account has", "we detected", "congratulations", "won a prize"]

# Known safe domains (for comparison)
TRUSTED_DOMAINS = ["google.com", "microsoft.com", "amazon.com"]

def extract_links(text):
    return re.findall(r"https?://\S+", text)

def domain_mismatch(sender_email, links):
    sender_domain = sender_email.split('@')[-1].lower()
    flagged = []
    for link in links:
        domain = urlparse(link).netloc.lower()
        if domain and sender_domain not in domain:
            flagged.append((link, domain))
    return flagged

def keyword_scan(text):
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in text.lower()]

def detect_urgent_language(text):
    return [phrase for phrase in URGENT_LANGUAGE if phrase in text.lower()]

def detect_poor_language(text):
    return [phrase for phrase in GRAMMAR_FLAGS if phrase in text.lower()]

def calculate_risk(sender_email, email_text):
    score = 0
    reasons = []

    # Rule 1: Keyword scan
    keywords = keyword_scan(email_text)
    if keywords:
        score += 30
        reasons.append(f"Suspicious keywords found: {', '.join(keywords)}")

    # Rule 2: Link analysis
    links = extract_links(email_text)
    mismatches = domain_mismatch(sender_email, links)
    if mismatches:
        score += 40
        reasons.append(f"Sender domain does not match link domains: {mismatches}")

    # Rule 3: Excessive links
    if len(links) > 3:
        score += 10
        reasons.append("Too many links present")

    # Rule 4: Urgent language detection
    urgent_flags = detect_urgent_language(email_text)
    if urgent_flags:
        score += 10
        reasons.append(f"Urgent language found: {', '.join(urgent_flags)}")

    # Rule 5: Poor grammar or generic greeting
    grammar_flags = detect_poor_language(email_text)
    if grammar_flags:
        score += 10
        reasons.append(f"Potentially suspicious language: {', '.join(grammar_flags)}")

    # Normalize score
    final_score = min(score, 100)
    return final_score, reasons

def fetch_emails_from_gmail(username, password, n=5):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(username, password)
        mail.select("inbox")

        result, data = mail.search(None, "ALL")
        email_ids = data[0].split()[-n:]
        for email_id in email_ids:
            result, data = mail.fetch(email_id, "(RFC822)")
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            sender = msg["From"]
            subject = msg["Subject"]
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode(errors='ignore')
            else:
                body = msg.get_payload(decode=True).decode(errors='ignore')

            print(f"\nFrom: {sender}\nSubject: {subject}")
            score, reasons = calculate_risk(sender, body)
            print("Phishing Risk Score:", score)
            for reason in reasons:
                print("-", reason)

        mail.logout()
    except Exception as e:
        print("Error fetching emails:", e)

def fetch_emails_from_outlook():
    print("Outlook support will require Microsoft Graph API integration. Placeholder for future implementation.")

if __name__ == "__main__":
    sender = "security@micr0s0ft-support.com"
    email_body = """
    Dear customer,

    Your account has been locked due to suspicious activity. Please act now to verify your account.
    Click here: http://fake-microsoft.com/verify

    Thank you,
    Microsoft Support
    """

    risk_score, flags = calculate_risk(sender, email_body)

    print("Phishing Risk Score:", risk_score)
    print("Reasons:")
    for reason in flags:
        print("-", reason)

    # Uncomment to fetch from Gmail
    # fetch_emails_from_gmail("your_email@gmail.com", "your_password")

    # Placeholder call for Outlook integration
    # fetch_emails_from_outlook()