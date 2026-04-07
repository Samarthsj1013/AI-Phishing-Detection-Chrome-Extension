import pandas as pd
import re
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# load data
df = pd.read_csv("data/phishing.csv")

# feature extraction
def extract_features(url):
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        1 if 'https' in url else 0,
        1 if re.search(r'login|verify|secure', url) else 0
    ]

X = df['url'].apply(extract_features).tolist()
y = df['label']

# split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# train
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# test
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("✅ Accuracy:", accuracy)

# save
joblib.dump(model, "model/model.pkl")