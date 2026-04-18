import pandas as pd
import numpy as np
import re
import joblib
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

# ── Load dataset ──────────────────────────────────────────────
df = pd.read_csv("data/dataset_phishing.csv")
print(f"Dataset loaded: {df.shape[0]} rows")
print(f"Label distribution:\n{df['status'].value_counts()}\n")

# ── Feature extraction (20 features) ─────────────────────────
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

FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_hyphens', 'has_https', 'suspicious_keywords',
    'has_at', 'has_ip', 'num_subdomains', 'domain_length', 'suspicious_tld',
    'num_slashes', 'num_special_chars', 'double_slash_redirect', 'path_length',
    'digits_in_domain', 'has_www', 'num_query_params', 'is_url_shortener',
    'num_underscores', 'digit_ratio'
]

# ── Prepare data ──────────────────────────────────────────────
print("Extracting features from 11,430 URLs (takes ~30 seconds)...")
X = df['url'].apply(extract_features).tolist()

le = LabelEncoder()
y = le.fit_transform(df['status'])  # legitimate=0, phishing=1
print(f"Classes: {le.classes_}\n")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train ─────────────────────────────────────────────────────
print("Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────
y_pred = model.predict(X_test)

print("\n" + "="*50)
print("MODEL EVALUATION")
print("="*50)
print(f"Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision : {precision_score(y_test, y_pred):.4f}")
print(f"Recall    : {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score  : {f1_score(y_test, y_pred):.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1')
print(f"\n5-Fold CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

# ── Confusion matrix ──────────────────────────────────────────
os_makedirs = __import__('os').makedirs
os_makedirs('model', exist_ok=True)

cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Legitimate', 'Phishing'],
            yticklabels=['Legitimate', 'Phishing'])
plt.title('Confusion Matrix')
plt.ylabel('Actual')
plt.xlabel('Predicted')
plt.tight_layout()
plt.savefig('model/confusion_matrix.png')
print("\nSaved: model/confusion_matrix.png")

# ── Feature importance ────────────────────────────────────────
feat_df = pd.DataFrame({'feature': FEATURE_NAMES, 'importance': model.feature_importances_})
feat_df = feat_df.sort_values('importance', ascending=False)

plt.figure(figsize=(10, 6))
sns.barplot(data=feat_df, x='importance', y='feature', palette='viridis')
plt.title('Feature Importance')
plt.tight_layout()
plt.savefig('model/feature_importance.png')
print("Saved: model/feature_importance.png")

# ── Save ──────────────────────────────────────────────────────
joblib.dump(model, "model/model.pkl")
joblib.dump(le, "model/label_encoder.pkl")
joblib.dump(FEATURE_NAMES, "model/feature_names.pkl")

print("\n✅ Model trained and saved!")
print(f"Training samples : {len(X_train)}")
print(f"Test samples     : {len(X_test)}")