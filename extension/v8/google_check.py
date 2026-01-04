
import os
import requests
import sys
from dotenv import load_dotenv

def check_google_safe_browsing(url, api_key):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-links-detector-simple",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        print("[Google API Response]:")
        print(data)
        if data.get("matches"):
            print(f"[ALERT] URL flagged as unsafe by Google Safe Browsing: {url}")
            return True
        else:
            print(f"[OK] URL not flagged: {url}")
            return False
    except Exception as e:
        print(f"[ERROR] Safe Browsing check failed: {e}")
        return False

if __name__ == "__main__":
    load_dotenv()
    if len(sys.argv) < 2:
        print("Usage: python google_check.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        print("Error: GOOGLE_SAFE_BROWSING_API_KEY not set in .env file.")
        sys.exit(1)
    check_google_safe_browsing(url, api_key)
