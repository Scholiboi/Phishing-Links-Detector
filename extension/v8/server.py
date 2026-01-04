# --- GOOGLE SAFE BROWSING INTEGRATION ---
def check_google_safe_browsing(url, api_key):
    """
    Checks the URL against Google Safe Browsing API.
    Returns True if the URL is flagged as unsafe, False otherwise.
    """
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-links-detector",
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
        return data
    except Exception as e:
        print(f"[SafeBrowsing] Error checking URL: {e}")
        return False
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import random
import sqlite3
import os
import joblib
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import shap  # Import the SHAP library
import warnings
from dotenv import load_dotenv
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")


# --- SQLITE BLOCKLIST DB SETUP ---

DB_PATH = 'blocklist.db'
app = Flask(__name__)
CORS(app)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if not os.path.exists(DB_PATH):
        conn = get_db_connection()
        conn.execute('CREATE TABLE domain_status (domain TEXT PRIMARY KEY, status INTEGER)')
        # Insert some mock data: 0 = blocklist, 1 = whitelist
        conn.executemany('INSERT INTO domain_status (domain, status) VALUES (?, ?)', [
            ("badphishingsite.com", 0),
            ("maliciousdomain.net", 0),
            ("evilsite.org", 0),
            ("google.com", 1),
            ("github.com", 1)
        ])
        conn.commit()
        conn.close()


load_dotenv()
init_db()


# --- CONFIGURATION ---
MODEL_PATH = 'xgboost_phishing_model_v2_random_f1_tuned.joblib'

# A list of known URL shortening services.
SHORTENING_SERVICES = [
    'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd',
    'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
    'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.mp', 'lnkd.in',
    'db.tt', 'qr.ae', 'adf.ly', 'goo.by', 'bitly.com', 'cur.lv', 'tiny.cc', 'alturl.com', 'buff.ly'
]


# --- FEATURE EXTRACTION ENGINE ---

def count_special_chars(text):
    """Counts the occurrences of various special characters in a string."""
    return {
        'qty_dot': text.count('.'), 'qty_hyphen': text.count('-'), 'qty_underline': text.count('_'),
        'qty_slash': text.count('/'), 'qty_questionmark': text.count('?'), 'qty_equal': text.count('='),
        'qty_at': text.count('@'), 'qty_and': text.count('&'), 'qty_exclamation': text.count('!'),
        'qty_space': text.count(' '), 'qty_tilde': text.count('~'), 'qty_comma': text.count(','),
        'qty_plus': text.count('+'), 'qty_asterisk': text.count('*'), 'qty_hashtag': text.count('#'),
        'qty_dollar': text.count('$'), 'qty_percent': text.count('%'),
    }

def get_url_features(url):
    """
    Extracts features from a given URL that can be calculated instantly.
    """
    features = {}
    
    # Parse the URL to extract domain
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.lower().replace('www.', '')
    except:
        domain = ''
    
    # List of trusted domains that should be analyzed by domain only, not full URL
    # This prevents false positives for legitimate services with dynamic URLs
    TRUSTED_DOMAINS = {
        'google.com', 'youtube.com', 'gmail.com', 'meet.google.com', 'docs.google.com',
        'drive.google.com', 'calendar.google.com', 'maps.google.com', 'translate.google.com',
        'microsoft.com', 'outlook.com', 'teams.microsoft.com', 'office.com',
        'zoom.us', 'slack.com', 'discord.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'reddit.com', 'twitter.com', 'facebook.com', 'instagram.com',
        'linkedin.com', 'amazon.com', 'netflix.com', 'spotify.com', 'apple.com'
    }
    
    # Check if this is a trusted domain or subdomain
    is_trusted = False
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith('.' + trusted):
            is_trusted = True
            break
    
    # For trusted domains, analyze only the domain, not the full URL with paths
    if is_trusted:
        print(f"[TRUSTED DOMAIN] Analyzing domain only: {domain}")
        # Create a clean URL with just the domain for analysis
        analysis_url = domain
    else:
        # For unknown domains, analyze the full URL
        analysis_url = url.strip()
        # Remove protocol (http:// or https://) but keep the rest intact
        analysis_url = re.sub(r'^https?://', '', analysis_url)
        # Remove www. prefix only if present
        analysis_url = re.sub(r'^www\.', '', analysis_url)
        # Remove trailing slash if it's the only path component
        if analysis_url.endswith('/') and analysis_url.count('/') == 1:
            analysis_url = analysis_url[:-1]
    
    # Use the analysis URL for feature extraction
    original_url = analysis_url

    url_chars = count_special_chars(original_url)
    for key, value in url_chars.items():
        features[f'{key}_url'] = value
    features['length_url'] = len(original_url)

    # Add protocol back for parsing
    parse_url = 'http://' + analysis_url

    try:
        parsed_url = urlparse(parse_url)
        domain = parsed_url.netloc
        path = parsed_url.path
        params = parsed_url.query
        directory, file = os.path.split(path)
        if directory.startswith('/'):
            directory = directory[1:]
    except Exception:
        print(f"Warning: Could not parse URL '{parse_url}'.")
        return {}

    try:
        tld = domain.split('.')[-1].split(':')[0]
        features['qty_tld_url'] = len(tld)
    except IndexError:
        tld = ''
        features['qty_tld_url'] = 0

    domain_chars = count_special_chars(domain)
    for key, value in domain_chars.items():
        features[f'{key}_domain'] = value
    features['qty_vowels_domain'] = sum(1 for char in domain if char in 'aeiouAEIOU')
    features['domain_length'] = len(domain)
    features['domain_in_ip'] = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0
    features['server_client_domain'] = 1 if 'server' in domain.lower() or 'client' in domain.lower() else 0

    dir_chars = count_special_chars(directory)
    for key, value in dir_chars.items():
        features[f'{key}_directory'] = value
    features['directory_length'] = len(directory) if directory else 0

    file_chars = count_special_chars(file)
    for key, value in file_chars.items():
        features[f'{key}_file'] = value
    features['file_length'] = len(file) if file else 0

    param_chars = count_special_chars(params)
    for key, value in param_chars.items():
        features[f'{key}_params'] = value
    features['params_length'] = len(params) if params else 0
    features['tld_present_params'] = 1 if params and tld and tld in params else 0
    features['qty_params'] = len(parse_qs(params))

    features['email_in_url'] = 1 if '@' in original_url else 0
    features['url_shortened'] = 1 if domain in SHORTENING_SERVICES else 0

    return features


# --- MODEL AND EXPLAINER LOADING ---

def load_model_and_explainer():
    """Loads the model, its features, and creates a SHAP explainer."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            data = joblib.load(MODEL_PATH)
        
        model = data['model']
        expected_features = data['features']

        # Create a SHAP explainer for our tree-based model (XGBoost)
        explainer = shap.TreeExplainer(model)

        return model, expected_features, explainer
    except FileNotFoundError:
        print(f"Error: Model file not found at '{MODEL_PATH}'")
        print("Please run the 'retrain_model...' script first.")
        return None, None, None
    except Exception as e:
        print(f"An error occurred loading the model file: {e}")
        return None, None, None


# --- PREDICTION AND EXPLANATION ---

def explain_prediction(url, model, expected_features, explainer):
    """Takes a URL, predicts, and provides a SHAP-based explanation."""
    if not url: return

    extracted_features = get_url_features(url)
    if not extracted_features: return

    # Prepare the DataFrame for prediction
    live_df = pd.DataFrame([extracted_features])
    live_df = live_df.reindex(columns=expected_features, fill_value=0)

    # --- Prediction ---
    prediction = model.predict(live_df)[0]
    probabilities = model.predict_proba(live_df)[0]
    result_text = "PHISHING" if prediction == 1 else "Legitimate"
    confidence = probabilities[prediction] * 100

    print(f"\nURL: '{url}'")
    print(f"Prediction: {result_text} (Confidence: {confidence:.2f}%)")

    # --- Explanation ---
    # Calculate SHAP values for this specific prediction
    shap_values = explainer.shap_values(live_df)

    # Combine feature names, their actual values for this URL, and their SHAP values
    feature_values = live_df.iloc[0]
    shap_series = pd.Series(shap_values[0], index=expected_features)

    # Sort features by the absolute magnitude of their impact
    sorted_shap = shap_series.abs().sort_values(ascending=False)

    print("\n--- Reasoning ---")
    print("Top features influencing this decision (from most to least impactful):")

    # Display the top 5 most influential features
    for feature in sorted_shap.head(5).index:
        shap_val = shap_series[feature]
        feat_val = feature_values[feature]

        # Only show features that actually had a non-zero value
        if feat_val != 0:
            if shap_val > 0:
                direction = "increases risk of PHISHING"
            else:
                direction = "decreases risk (suggests Legitimate)"

            print(f"  - Feature '{feature}' (value: {feat_val}) -> {direction}")


# --- DOMAIN STATUS ENDPOINT ---

@app.route('/domain_status', methods=['POST'])
def domain_status():
    """Endpoint to check the status of a domain using XGBoost model."""
    data = request.get_json()
    url = data.get('url')
    domain = data.get('domain')
    
    # Use URL if provided, otherwise construct from domain
    if not url and domain:
        url = f"http://{domain}"
    elif not url and not domain:
        return jsonify({'error': 'URL or domain required'}), 400

    # Log the received query
    print(f"\n[QUERY] Received request for URL: {url}")
    if domain:
        print(f"[QUERY] Domain parameter: {domain}")


    # Trusted domain logic (reuse from get_url_features)
    TRUSTED_DOMAINS = {
        'google.com', 'youtube.com', 'gmail.com', 'meet.google.com', 'docs.google.com','amazon.in',
        'drive.google.com', 'calendar.google.com', 'maps.google.com', 'translate.google.com',
        'microsoft.com', 'outlook.com', 'teams.microsoft.com', 'office.com',
        'zoom.us', 'slack.com', 'discord.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'reddit.com', 'twitter.com', 'facebook.com', 'instagram.com',
        'linkedin.com', 'amazon.com', 'netflix.com', 'spotify.com', 'apple.com'
    }
    is_trusted = False
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain_only = parsed.netloc.lower().replace('www.', '')
    except:
        domain_only = ''
    for trusted in TRUSTED_DOMAINS:
        if domain_only == trusted or domain_only.endswith('.' + trusted):
            is_trusted = True
            break

    # --- Google Safe Browsing for non-trusted domains ---
    GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY')
    google_response = None
    google_flagged = False
    if GOOGLE_SAFE_BROWSING_API_KEY:
        google_response = check_google_safe_browsing(url, GOOGLE_SAFE_BROWSING_API_KEY)
        google_flagged = bool(google_response.get("matches")) if google_response else False
        if google_flagged:
            print(f"[SafeBrowsing] URL flagged as unsafe by Google Safe Browsing: {url}")

    # BYPASS MODEL if trusted and not flagged by Google
    if is_trusted and not google_flagged:
        print(f"[TRUSTED BYPASS] {url} is trusted and not flagged by Google. Bypassing model.")
        return jsonify({
            'url': url,
            'google_safe_browsing': google_response,
            'google_flagged': google_flagged,
            'model_prediction': 'TRUSTED DOMAIN',
            'model_confidence': None,
            'model_status': 1,
            'model_reasoning': ['Trusted domain and not flagged by Google Safe Browsing.']
        })

    model, expected_features, explainer = load_model_and_explainer()
    if not model or not explainer:
        return jsonify({'error': 'Model loading failed'}), 500

    extracted_features = get_url_features(url)
    if not extracted_features:
        return jsonify({'error': 'Feature extraction failed'}), 400

    live_df = pd.DataFrame([extracted_features])
    live_df = live_df.reindex(columns=expected_features, fill_value=0)

    prediction = model.predict(live_df)[0]
    probabilities = model.predict_proba(live_df)[0]
    result_text = "PHISHING" if prediction == 1 else "Legitimate"
    confidence = float(probabilities[prediction] * 100)

    # Generate SHAP explanations
    shap_values = explainer.shap_values(live_df)
    feature_values = live_df.iloc[0]
    shap_series = pd.Series(shap_values[0], index=expected_features)

    # Get top 5 most influential features
    sorted_shap = shap_series.abs().sort_values(ascending=False)
    reasoning = []

    for feature in sorted_shap.head(5).index:
        shap_val = shap_series[feature]
        feat_val = feature_values[feature]

        # Only include features that had a non-zero value
        if feat_val != 0:
            if shap_val > 0:
                direction = "increases phishing risk"
            else:
                direction = "decreases phishing risk"

            reasoning.append({
                'feature': feature.replace('_', ' ').title(),
                'value': float(feat_val) if hasattr(feat_val, 'item') else float(feat_val),
                'impact': direction,
                'shap_value': float(shap_val) if hasattr(shap_val, 'item') else float(shap_val)
            })

    # Return status: 0 = block (phishing), 1 = allow (legitimate)
    status = 0 if prediction == 1 else 1

    # Log the prediction result
    print(f"[RESULT] Prediction: {result_text} (Confidence: {confidence:.2f}%) - Status: {status}")
    print(f"[RESULT] Top reasoning features: {len(reasoning)} features identified")

    return jsonify({
        'url': url,
        'google_safe_browsing': google_response,
        'google_flagged': google_flagged,
        'model_prediction': result_text,
        'model_confidence': confidence,
        'model_status': status,
        'model_reasoning': reasoning
    })


# --- ALL DOMAINS AND STATUS ENDPOINT ---
@app.route('/all_domains', methods=['GET'])
def all_domains():
    conn = get_db_connection()
    rows = conn.execute('SELECT domain, status FROM domain_status').fetchall()
    conn.close()
    result = [{"domain": row["domain"], "status": row["status"]} for row in rows]
    return jsonify(result)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
 