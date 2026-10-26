"""
Scan 8+ URLs through the running PhishGuard AI API
=================================================
Sends test URLs to http://127.0.0.1:5000/api/predict via HTTP POST.
Does NOT visit or fetch URLs, only evaluates text structure.
"""
import urllib.request
import json

test_urls = [
    # 4 Well-known legitimate URLs
    ("https://www.google.com", "Legitimate (Google)"),
    ("https://github.com", "Legitimate (GitHub)"),
    ("https://en.wikipedia.org", "Legitimate (Wikipedia)"),
    ("https://www.stanford.edu", "Legitimate (Stanford University)"),
    # Variant checks for domain format comparison
    ("google.com", "Legitimate (no scheme/www)"),
    ("https://www.github.com", "Legitimate (with www)"),
    # 4 Obviously phishing-style made-up URLs
    ("http://192.168.1.100/secure/login.php", "Phishing (IP host + login)"),
    ("http://paypal-account-verification.security-update-2026.com/login/verify.php?session=9382103", "Phishing (long + login/verify)"),
    ("http://user:password@malicious-bank-login.xyz/account/confirm", "Phishing (@ trick + confirm)"),
    ("http://apple-id-suspended.support-center.top/recovery/auth.html", "Phishing (odd TLD .top + suspended)"),
]

def main():
    print("=" * 115)
    print(f"{'#':<3} | {'Category':<32} | {'URL':<50} | {'Prediction':<10} | {'Confidence':<10} | {'Risk Level':<10}")
    print("=" * 115)

    for i, (url, category) in enumerate(test_urls, 1):
        req = urllib.request.Request(
            "http://127.0.0.1:5000/api/predict",
            data=json.dumps({"url": url}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                pred = data.get("prediction", "N/A")
                conf = data.get("confidence_str", f"{data.get('confidence')}%")
                risk = data.get("risk_level", "N/A")
                print(f"{i:<3} | {category:<32} | {url[:48]:<50} | {pred:<10} | {conf:<10} | {risk:<10}")
        except Exception as e:
            print(f"{i:<3} | {category:<32} | {url[:48]:<50} | ERROR: {e}")

    print("=" * 115)

if __name__ == "__main__":
    main()
