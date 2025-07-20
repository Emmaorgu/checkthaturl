import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
df = pd.read_csv("phishing_dataset.csv")

# Basic info
print("🧾 Dataset shape:", df.shape)
print("\n📊 Label distribution:")
print(df['label'].value_counts())

# Plot label distribution
sns.countplot(data=df, x='label')
plt.title("Phishing vs Legitimate Website Count")
plt.xticks([0, 1], ['Legitimate (0)', 'Phishing (1)'])
plt.ylabel("Count")
plt.xlabel("Label")
plt.show()

# Check for nulls
print("\n🕳️ Null value check:")
print(df.isnull().sum())

# Sample preview
print("\n🔍 First few rows:")
print(df.head())
