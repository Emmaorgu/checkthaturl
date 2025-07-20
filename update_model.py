import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

# -------------------------------
# 🔍 Custom Feature Extraction Function
# -------------------------------
def extract_features(url):
    return {
        'url_length': len(url),
        'has_https': int('https' in url.lower()),
        'count_dots': url.count('.'),
        'count_hyphens': url.count('-'),
        'count_digits': sum(char.isdigit() for char in url),
        'has_suspicious_word': int(any(word in url.lower() for word in ['login', 'verify', 'secure', 'bvn', 'update', 'free', 'alert'])),
        'ends_with_com': int(url.lower().endswith('.com')),
    }

# -------------------------------
# ✅ Load URLs
# -------------------------------
def load_urls(file_path):
    if not os.path.exists(file_path):
        print(f"⚠️ {file_path} not found.")
        return []
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

legit_urls = load_urls('legitimate_urls.txt')
phish_urls = load_urls('real_phishing_urls.txt')

# -------------------------------
# 🧪 Feature Extraction
# -------------------------------
def create_dataset(urls, label):
    data = []
    for url in urls:
        features = extract_features(url)
        features['url'] = url
        features['label'] = label
        data.append(features)
    return pd.DataFrame(data)

df_legit = create_dataset(legit_urls, label=0)
df_phish = create_dataset(phish_urls, label=1)

# -------------------------------
# 📦 Combine and Save Dataset
# -------------------------------
df_all = pd.concat([df_legit, df_phish], ignore_index=True)
df_all.to_csv('final_dataset.csv', index=False)
print("✅ final_dataset.csv saved.")

# -------------------------------
# 🤖 Train Model
# -------------------------------
X = df_all.drop(columns=['url', 'label'])
y = df_all['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# -------------------------------
# 📊 Evaluation
# -------------------------------
y_pred = model.predict(X_test)
print("\n🔍 Model Performance:\n")
print(classification_report(y_test, y_pred))

# -------------------------------
# 💾 Save Trained Model
# -------------------------------
joblib.dump(model, 'phishing_rf_model.pkl')
print("✅ phishing_rf_model.pkl saved.")
