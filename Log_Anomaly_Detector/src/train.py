import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

DATA_PATH = "data/linux_auth_log_anomalies.csv"
MODEL_PATH = "models/anomaly_model.pkl"

def train():
    df = pd.read_csv(DATA_PATH)
    
    # Extract features from log data
    # Count errors and warnings per pod
    error_counts = df[df['log_level'] == 'ERROR'].groupby('pod_name').size().reset_index(name='error_count')
    warn_counts = df[df['log_level'] == 'WARN'].groupby('pod_name').size().reset_index(name='warn_count')
    debug_counts = df[df['log_level'] == 'DEBUG'].groupby('pod_name').size().reset_index(name='debug_count')
    
    # Merge all counts
    X = error_counts.merge(warn_counts, on='pod_name', how='outer').merge(debug_counts, on='pod_name', how='outer')
    X = X.fillna(0)
    X = X[['error_count', 'warn_count', 'debug_count']]

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    os.makedirs('models', exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print("Anomaly detection model saved.")

if __name__ == "__main__":
    train()