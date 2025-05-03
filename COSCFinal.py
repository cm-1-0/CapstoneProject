import re
import pickle
import numpy as np
from urllib.parse import urlparse
import imaplib
import email
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from sklearn.base import BaseEstimator, TransformerMixin

# --- Add ExtraFeatures for unpickling the model ---
class ExtraFeatures(BaseEstimator, TransformerMixin):
    def fit(self, x, y=None):
        return self

    def transform(self, texts):
        features = []
        for text in texts:
            text = text.lower()
            num_links = len(re.findall(r'https?://', text))
            urgent_keywords = ["urgent", "immediately", "act now", "response required"]
            has_urgent = int(any(word in text for word in urgent_keywords))
            has_suspicious_phrase = int("verify your account" in text or "click the link" in text)
            features.append([num_links, has_urgent, has_suspicious_phrase])
        return np.array(features)

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

    final_score = min(score, 100)
    return final_score, reasons

def ml_detect(email_text):
    try:
        with open("phishing_ml_model.pkl", "rb") as f:
            model = pickle.load(f)
        prediction = model.predict([email_text])[0]
        prob = model.predict_proba([email_text])[0]
        confidence = max(prob) * 100
        label = "Phishing" if prediction == 1 else "Legitimate"
        return label, confidence
    except Exception as e:
        return "Error", str(e)

def run_gui():
    def analyze_email():
        sender = sender_entry.get()
        body = body_text.get("1.0", tk.END).strip()
        method = detection_method.get()

        result_text.delete("1.0", tk.END)

        if method == "Rule-Based":
            score, reasons = calculate_risk(sender, body)
            result_text.insert(tk.END, f"Rule-Based Detection\nPhishing Risk Score: {score}\n")
            for reason in reasons:
                result_text.insert(tk.END, f"- {reason}\n")

        elif method == "AI-Based":
            label, confidence = ml_detect(body)
            if isinstance(confidence, float):
                result_text.insert(tk.END, f"AI-Based Detection\nPrediction: {label}\nConfidence: {confidence:.2f}%\n")
            else:
                result_text.insert(tk.END, f"AI-Based Detection Failed:\n{confidence}\n")

    window = tk.Tk()
    window.title("Phishing Email Detector")

    tk.Label(window, text="Sender Email:").pack()
    sender_entry = tk.Entry(window, width=60)
    sender_entry.pack()

    tk.Label(window, text="Email Body:").pack()
    body_text = scrolledtext.ScrolledText(window, width=70, height=10)
    body_text.pack()

    tk.Label(window, text="Detection Method:").pack()
    detection_method = ttk.Combobox(window, values=["Rule-Based", "AI-Based"])
    detection_method.current(0)
    detection_method.pack()

    tk.Button(window, text="Analyze", command=analyze_email).pack(pady=10)

    tk.Label(window, text="Results:").pack()
    result_text = scrolledtext.ScrolledText(window, width=70, height=10)
    result_text.pack()

    window.mainloop()

if __name__ == "__main__":
    run_gui()
