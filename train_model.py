import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
from imblearn.over_sampling import SMOTE
import joblib

# Load dataset
df = pd.read_csv("dataset/phishing_dataset.csv")

# Fill missing WHOIS fields and encode
df['whois_registrar'] = df['whois_registrar'].fillna('unknown').str.lower()
df['whois_country'] = df['whois_country'].fillna('unknown').str.lower()

label_enc_registrar = LabelEncoder()
label_enc_country = LabelEncoder()

df['whois_registrar'] = label_enc_registrar.fit_transform(df['whois_registrar'])
df['whois_country'] = label_enc_country.fit_transform(df['whois_country'])

# Save the encoders
joblib.dump(label_enc_registrar, "registrar_encoder.pkl")
joblib.dump(label_enc_country, "country_encoder.pkl")

# Drop non-numeric or non-feature columns
X = df.drop(columns=['label', 'url', 'high_risk_keywords', 'contextual_keywords'], errors='ignore')
y = df['label']

# Fill any remaining NaNs
X = X.fillna(0)

# Balance dataset using SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Split into train/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.2, stratify=y_resampled, random_state=42
)

# Train Random Forest
model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
print("\n🔍 Classification Report:\n", classification_report(y_test, y_pred))
print("📉 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Cross-validation
cv_scores = cross_val_score(model, X_resampled, y_resampled, cv=5)
print(f"\n✅ Cross-Validation Accuracy: {cv_scores.mean():.2f} ± {cv_scores.std():.2f}")

# Save trained model
joblib.dump(model, "phishing_rf_model.pkl")
print("✅ Model saved as phishing_rf_model.pkl")
