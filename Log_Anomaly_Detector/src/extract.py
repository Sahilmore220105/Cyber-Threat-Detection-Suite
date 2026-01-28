import pandas as pd

def preprocess_logs(df):
    """Converts raw log categorical data into numeric features."""
    # Example: Convert 'status' to 1 (failed) or 0 (success)
    df['is_failed'] = df['status'].apply(lambda x: 1 if 'fail' in str(x).lower() else 0)
    # Feature: Login attempts per IP
    features = df.groupby('ip_address').agg({
        'is_failed': ['count', 'sum']
    })
    features.columns = ['total_attempts', 'failed_attempts']
    return features