from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re
import tldextract
import shap
import numpy as np
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', '*')
    response.headers.add('Access-Control-Allow-Methods', '*')
    return response

# ── Load model + metadata ─────────────────────────────────────
model = joblib.load("model/model.pkl")
le = joblib.load("model/label_encoder.pkl")
FEATURE_NAMES = joblib.load("model/feature_names.pkl")

explainer = shap.TreeExplainer(model)

# ── Feature extraction ────────────────────────────────────────
def extract_features(url):
    url = str(url)
    ext = tldextract.extract(url)

    suspicious_words = ['login', 'verify', 'secure', 'account', 'update',
                        'banking', 'confirm', 'password', 'signin', 'webscr',
                        'ebayisapi', 'paypal', 'free', 'lucky', 'bonus']

    return [
        len(url),
        url.count('.'),
        url.count('-'),
        1 if url.startswith('https') else 0,
        sum(1 for w in suspicious_words if w in url.lower()),
        1 if '@' in url else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        len(ext.subdomain.split('.')) if ext.subdomain else 0,
        len(ext.domain) if ext.domain else 0,
        1 if ext.suffix in ['tk','ml','ga','cf','gq','xyz','top','work','click'] else 0,
        url.count('/'),
        len(re.findall(r'[!$%^&*()+=\[\]{};\'\"\\|,<>?]', url)),
        1 if '//' in url[7:] else 0,
        len(url.split('/')[-1]),
        sum(c.isdigit() for c in ext.domain) if ext.domain else 0,
        1 if 'www' in url.lower() else 0,
        url.count('?') + url.count('&'),
        1 if ext.domain in ['bit','tinyurl','goo','t','ow','tiny','is'] else 0,
        url.count('_'),
        round(sum(c.isdigit() for c in url) / len(url), 3) if len(url) > 0 else 0
    ]

# ── SHAP reasons ──────────────────────────────────────────────
def get_shap_reasons(features, prediction):
    try:
        shap_values = explainer.shap_values(np.array([features]))

        if isinstance(shap_values, list):
            raw = shap_values[1][0]
        else:
            raw = shap_values[0]

        values = [float(v) if not isinstance(v, (list, np.ndarray)) else float(np.array(v).flatten()[1]) for v in raw]

        feature_impacts = list(zip(FEATURE_NAMES, values, features))
        feature_impacts.sort(key=lambda x: abs(x[1]), reverse=True)

        reason_map = {
            'url_length': lambda v, f: f"Unusually long URL ({int(f)} chars)" if int(f) > 60 else None,
            'num_dots': lambda v, f: f"Excessive dots in URL ({int(f)})" if int(f) > 4 else None,
            'num_hyphens': lambda v, f: f"Too many hyphens ({int(f)})" if int(f) > 2 else None,
            'has_https': lambda v, f: "Not using HTTPS (insecure)" if int(f) == 0 else None,
            'suspicious_keywords': lambda v, f: f"Contains {int(f)} suspicious keyword(s)" if int(f) > 0 else None,
            'has_at': lambda v, f: "URL contains @ symbol" if int(f) == 1 else None,
            'has_ip': lambda v, f: "URL uses IP address instead of domain" if int(f) == 1 else None,
            'num_subdomains': lambda v, f: f"Excessive subdomains ({int(f)})" if int(f) > 2 else None,
            'suspicious_tld': lambda v, f: "Uses suspicious top-level domain" if int(f) == 1 else None,
            'double_slash_redirect': lambda v, f: "URL contains redirect pattern" if int(f) == 1 else None,
            'is_url_shortener': lambda v, f: "URL shortener hides real destination" if int(f) == 1 else None,
            'digit_ratio': lambda v, f: f"High ratio of digits ({float(f):.1%})" if float(f) > 0.3 else None,
            'num_query_params': lambda v, f: f"Many query parameters ({int(f)})" if int(f) > 3 else None,
        }

        reasons = []
        for feat_name, shap_val, feat_val in feature_impacts[:5]:
            if feat_name in reason_map and abs(shap_val) > 0.01:
                reason = reason_map[feat_name](shap_val, feat_val)
                if reason:
                    reasons.append({
                        "reason": reason,
                        "impact": "high" if abs(shap_val) > 0.1 else "medium",
                        "shap_value": round(shap_val, 4)
                    })

        return reasons[:4]

    except Exception as e:
        print(f"SHAP error: {e}")
        import traceback
        traceback.print_exc()
        return []

# ── Routes ────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running", "model": "PhishGuard AI v2"})

@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"})

    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data.get("url", "").strip()

    # Strip tracking parameters
    if '?' in url:
        base = url.split('?')[0]
        params = url.split('?')[1]
        clean_params = '&'.join(p for p in params.split('&')
                                if not any(t in p.lower() for t in ['zx=', 'utm_', 'fbclid', 'gclid']))
        url = base + ('?' + clean_params if clean_params else '')

    # Handle local/internal URLs
    if any(x in url for x in ['127.0.0.1', 'localhost', 'chrome://', 'chrome-extension://']):
        return jsonify({
            "url": url,
            "result": "Safe",
            "risk_level": "none",
            "confidence": 100.0,
            "reasons": [],
            "note": "Local or internal URL"
        })

    try:
        features = extract_features(url)
        prediction = model.predict([features])[0]
        prob = model.predict_proba([features])[0]

        phishing_confidence = round(float(prob[1]) * 100, 2)
        safe_confidence = round(float(prob[0]) * 100, 2)

        # Raise threshold to 70% to reduce false positives
        result = "Phishing" if phishing_confidence >= 70 else "Safe"
        risk_level = "none" if result == "Safe" else (
            "high" if phishing_confidence >= 80 else "medium"
        )

        reasons = get_shap_reasons(features, prediction) if result == "Phishing" else []

        return jsonify({
            "url": url,
            "result": result,
            "risk_level": risk_level,
            "confidence": phishing_confidence if result == "Phishing" else safe_confidence,
            "reasons": reasons
        })

    except Exception as e:
        print(f"Analysis error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)