"""
Test saved model on 10 benchmark URLs:
  - 5 known legitimate
  - 5 obviously suspicious made-up ones
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.predictor import predict_url

urls = [
    # 5 Legitimate URLs
    "https://www.google.com",
    "https://github.com",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    # 5 Suspicious Made-Up URLs
    "http://secure-login-paypal.com.account-update.xyz/verify.php",
    "http://192.168.1.100/bank-of-america/login.htm",
    "http://appleid.apple.com-verify-account.security-alert.top/signin",
    "http://signin.ebay.com.update-account.tk/",
    "http://login.microsoftonline.com.account-recover.xyz/auth?user=test",
]

print("=" * 115)
print(f"{'#':<3} | {'Type':<12} | {'URL':<65} | {'Prediction':<10} | {'Confidence':<10} | {'Risk Level'}")
print("=" * 115)

for i, u in enumerate(urls, 1):
    url_type = "Legitimate" if i <= 5 else "Suspicious"
    res = predict_url(u)
    pred = res.get("prediction", "ERROR")
    conf = res.get("confidence_str", "N/A")
    risk = res.get("risk_level", "N/A")
    print(f"{i:<3} | {url_type:<12} | {u:<65} | {pred:<10} | {conf:<10} | {risk}")

print("=" * 115)

# Supplementary: www. comparison to demonstrate the dataset artifact
print("\n[DATASET ARTIFACT DEMONSTRATION] Effect of 'www.' on legitimate domains:")
print("-" * 115)
for u in ["https://www.github.com", "https://www.wikipedia.org"]:
    res = predict_url(u)
    print(f"    | Legitimate   | {u:<65} | {res['prediction']:<10} | {res['confidence_str']:<10} | {res['risk_level']}")
print("-" * 115)
