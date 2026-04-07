from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re

# create app
app = Flask(__name__)

# enable CORS properly
CORS(app, resources={r"/*": {"origins": "*"}})
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', '*')
    response.headers.add('Access-Control-Allow-Methods', '*')
    return response

# load model
model = joblib.load("model/model.pkl")

# feature extraction
def extract_features(url):
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        1 if 'https' in url else 0,
        1 if re.search(r'login|verify|secure', url) else 0
    ]

# API route
@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    data = request.json
    url = data.get("url")

    features = extract_features(url)

    # prediction + probability
    prediction = model.predict([features])[0]
    prob = model.predict_proba([features])[0]

    confidence = round(max(prob) * 100, 2)

    result = "Phishing" if prediction == 1 else "Safe"

    # explainability
    reasons = []

    if "login" in url or "verify" in url or "secure" in url:
        reasons.append("Suspicious keywords in URL")

    if url.count('-') > 2:
        reasons.append("Too many hyphens in URL")

    if not url.startswith("https"):
        reasons.append("Website not using HTTPS")

    if len(url) > 60:
        reasons.append("Unusually long URL")

    return jsonify({
        "url": url,
        "result": result,
        "confidence": confidence,
        "reasons": reasons
    })
if "127.0.0.1" in url or "localhost" in url:
    result = "Safe"
    reasons = ["Local development environment"]
    confidence = 100
# run server
if __name__ == "__main__":
    app.run(debug=True)