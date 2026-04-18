# PhishGuard AI 🛡️

Chrome extension that tells you if a website is trying to phish you — before you get got.

## The idea
I kept seeing news about people falling for phishing links, and most browser warnings only catch sites that are already reported. I wanted something that could catch suspicious URLs before they're even in any database — using ML to analyze the URL structure itself.

## What actually happens when you click scan
1. The extension grabs the current tab's URL
2. Sends it to my Flask API running on Render
3. API runs it through a Random Forest model I trained on 11,430 URLs
4. Simultaneously checks it against VirusTotal (70+ security vendors)
5. Returns a verdict in under a second with the specific reasons

## Stack
- scikit-learn (Random Forest)
- SHAP for explainability
- VirusTotal API
- Flask + Render
- Chrome Extension (Manifest V3)

## Numbers
| Metric | Score |
|--------|-------|
| Accuracy | 90.07% |
| Precision | 88.62% |
| Recall | 91.95% |
| F1 Score | 90.25% |
| 5-Fold CV F1 | 90.21% ± 0.57% |

Tried XGBoost too — got 90.11% F1 vs Random Forest's 90.25%, so kept RF.

## Honest limitations
- URL-only analysis means a phisher with a clean domain and no suspicious patterns can slip through
- The free VirusTotal tier gives 500 requests/day which is fine for personal use but wouldn't scale
- Render free tier has a cold start delay of ~50 seconds if the API hasn't been hit in 15 minutes

## Running locally

```bash
pip install flask flask-cors scikit-learn pandas numpy joblib shap tldextract requests flask-limiter

python train.py  # only needed once
python app.py
```

Load the `extension/` folder in `chrome://extensions/` with Developer Mode on.

## Dataset
[Web Page Phishing Detection Dataset — Kaggle](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)