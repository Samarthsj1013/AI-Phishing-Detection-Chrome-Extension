# PhishGuard AI 🛡️

A Chrome Extension that detects phishing URLs in real time using a machine learning model I built and trained from scratch.

## What it does
When you're on any website, click the extension and it tells you whether the URL is safe or suspicious — along with the specific reasons why it was flagged.

## How it works
The extension sends the current tab's URL to a local Flask API, which runs it through a Random Forest model and returns a prediction with confidence score. The reasons shown aren't hardcoded — they come from SHAP values, which measure how much each feature actually pushed the model toward its decision.

## Stack
- Random Forest classifier (scikit-learn)
- SHAP TreeExplainer for explainability
- Flask REST API
- Chrome Extension (Manifest V3)

## Model metrics
Trained on 11,430 URLs (balanced — half phishing, half legitimate)

| Metric | Score |
|--------|-------|
| Accuracy | 90.07% |
| Precision | 88.62% |
| Recall | 91.95% |
| F1 Score | 90.25% |
| 5-Fold CV F1 | 90.21% ± 0.57% |

## Running it locally

```bash
# Install dependencies
pip install flask flask-cors scikit-learn pandas numpy joblib shap tldextract matplotlib seaborn

# Train the model (only needed once)
python train.py

# Start the backend
python app.py
```

Then go to `chrome://extensions/`, enable Developer Mode, click Load unpacked, and select the `extension/` folder.

## What I learned building this
Getting SHAP to work with RandomForest was trickier than expected — the shap_values output is a nested list structure that needed flattening before I could rank features by their actual contribution. The other thing that took time was false positives — URLs like Google's tracking parameters were triggering the model until I stripped them before analysis.

## Dataset
[Web Page Phishing Detection Dataset on Kaggle](https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset)