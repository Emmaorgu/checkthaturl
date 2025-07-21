import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# === CLI argument for dataset path ===
dataset_path = sys.argv[1] if len(sys.argv) > 1 else 'data/feature_dataset.csv'
model_output_path = 'model/phish_rf_model.pkl'

# === Load dataset ===
print(f"[+] Loading dataset from: {dataset_path}")
df = pd.read_csv(dataset_path)
print(f"[✓] Dataset loaded: {df.shape[0]} samples, {df.shape[1]} columns")

# === Drop non-numeric columns ===
non_numeric_cols = df.select_dtypes(include=['object']).columns.tolist()
if non_numeric_cols:
    print(f"[!] Dropping non-numeric columns: {non_numeric_cols}")
    df = df.drop(columns=non_numeric_cols)

# === Check for label ===
if 'label' not in df.columns:
    raise ValueError("[-] Dataset must contain a 'label' column.")

# === Split into features and label ===
X = df.drop(columns=['label'])
y = df['label']

# === Check for expected advanced features ===
expected_features = [
    'large_suspicious_image',
    'base64_image_detected',
    'ocr_alert_text_detected',
    'alert_image_followed_by_form_or_link',
    'link_density',
    'external_link_ratio',
    'mismatched_anchor_ratio',
    'keyword_density',
    'domain_entropy',
    'has_password_field',
    'form_with_suspicious_keywords',
    'has_js_timer',
    'has_html_timer',
    'timer_urgency_score'
]

missing_features = [feat for feat in expected_features if feat not in X.columns]
if missing_features:
    print(f"[!] Warning: Missing expected features: {missing_features}")
else:
    print("[✓] All critical features found, including countdown timer features.")

# === Split dataset ===
print("[+] Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

# === Train model ===
print("[+] Training Random Forest model...")
clf = RandomForestClassifier(n_estimators=200, max_depth=25, random_state=42)
clf.fit(X_train, y_train)
print("[✓] Model training complete.")

# === Evaluate model ===
print("\n[✓] Classification Report:")
print(classification_report(y_test, clf.predict(X_test)))

print("[✓] Confusion Matrix:")
print(confusion_matrix(y_test, clf.predict(X_test)))

# === Feature importance ===
print("\n[🔍] Feature Importances (Descending):")
importances = clf.feature_importances_
feature_names = X.columns
importance_data = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)

for feat, importance in importance_data:
    print(f"{feat:40} {importance:.4f}")

# === Save model ===
os.makedirs(os.path.dirname(model_output_path), exist_ok=True)
joblib.dump(clf, model_output_path)
print(f"[✓] Model saved to: {model_output_path}")
