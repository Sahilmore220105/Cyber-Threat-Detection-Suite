import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

# Paths
DATA_PATH = "data/PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = "python src/models/phishing_model.pkl"

def train_model():
    print("📥 Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    # Features (must match extract.py logic)
    features = [
        'URLLength',
        'NoOfLettersInURL',
        'NoOfDegitsInURL',
        'NoOfOtherSpecialCharsInURL'
    ]

    X = df[features]
    y = df['label']  # 1 = Phishing, 0 = Legitimate

    print("🧠 Training model...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )
    model.fit(X_train, y_train)

    # Ensure models folder exists
    os.makedirs("models", exist_ok=True)

    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Model saved successfully at: {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
