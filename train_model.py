import os
import sys
import joblib
import pandas as pd
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

dataset_path = sys.argv[1] if len(sys.argv) > 1 else 'data/feature_dataset.csv'
timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
model_output_dir = 'model'
model_output_path = os.path.join(model_output_dir, f'phish_rf_model_{timestamp}.pkl')

print(f"[+] Loading dataset from: {dataset_path}")
df = pd.read_csv(dataset_path)
print(f"[✓] Dataset loaded: {df.shape[0]} samples, {df.shape[1]} columns")

# Drop non-numeric
non_numeric_cols = df.select_dtypes(include=['object']).columns.tolist()
if non_numeric_cols:
    print(f"[!] Dropping non-numeric columns: {non_numeric_cols}")
    df = df.drop(columns=non_numeric_cols)

if 'label' not in df.columns:
    raise ValueError("[-] Dataset must contain a 'label' column.")

X = df.drop(columns=['label'])
y = df['label']

expected_features = [
    'large_suspicious_image','base64_image_detected','ocr_alert_text_detected','alert_image_followed_by_form_or_link',
    'link_density','external_link_ratio','mismatched_anchor_ratio','keyword_density','domain_entropy',
    'has_password_field','form_with_suspicious_keywords','has_js_timer','has_html_timer','timer_urgency_score',
    # Day-1/2 additions:
    'content_red_flags','link_red_flags','non_surface_red_flags','startup_like','phish_context_score'
]
missing = [c for c in expected_features if c not in X.columns]
print("[!] Missing expected features:" , missing) if missing else print("[✓] All critical features present (incl. Day-2 NLP).")

print("[+] Splitting dataset...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

print("[+] Training Random Forest...")
clf = RandomForestClassifier(
    n_estimators=300, max_depth=28, min_samples_leaf=2,
    class_weight="balanced_subsample", random_state=42
)
clf.fit(X_train, y_train)
print("[✓] Model training complete.")

print("\n[✓] Classification Report:")
print(classification_report(y_test, clf.predict(X_test)))
print("[✓] Confusion Matrix:")
print(confusion_matrix(y_test, clf.predict(X_test)))

print("\n[🔍] Top 25 Feature Importances:")
imp = clf.feature_importances_; names = X.columns
for name, val in sorted(zip(names, imp), key=lambda x: x[1], reverse=True)[:25]:
    print(f"{name:35} {val:.4f}")

os.makedirs(model_output_dir, exist_ok=True)
joblib.dump(clf, model_output_path)
print(f"[✓] Model saved to: {model_output_path}")
