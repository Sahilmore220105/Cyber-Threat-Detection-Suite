import streamlit as st
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import os

st.set_page_config(page_title="SOC Log Anomaly Detector", page_icon="🔍")
st.title("🔍 SOC Log Anomaly Detector")
st.write("Upload server authentication logs to identify suspicious IP behavior.")

# 1. Load the trained model
MODEL_PATH = "models/anomaly_model.pkl"
if not os.path.exists(MODEL_PATH):
    st.error("Model file not found! Please run 'python src/train.py' first.")
else:
    model = joblib.load(MODEL_PATH)

    # 2. Upload and Process Logs
    uploaded_log = st.file_uploader("Upload Auth Logs (CSV)", type="csv")
    
    if uploaded_log:
        df = pd.read_csv(uploaded_log)
        
        # Ensure the columns match training features
        required_cols = ['log_level', 'pod_name']
        if all(col in df.columns for col in required_cols):
            
            # Extract features from log data - same as training
            error_counts = df[df['log_level'] == 'ERROR'].groupby('pod_name').size().reset_index(name='error_count')
            warn_counts = df[df['log_level'] == 'WARN'].groupby('pod_name').size().reset_index(name='warn_count')
            debug_counts = df[df['log_level'] == 'DEBUG'].groupby('pod_name').size().reset_index(name='debug_count')
            
            # Merge all counts
            features_df = error_counts.merge(warn_counts, on='pod_name', how='outer').merge(debug_counts, on='pod_name', how='outer')
            features_df = features_df.fillna(0)
            features = features_df[['error_count', 'warn_count', 'debug_count']]
            
            # 3. Predict Anomalies
            features_df['anomaly_score'] = model.predict(features)
            # Mapping for readability: 1 -> Normal, -1 -> Anomaly
            features_df['Status'] = features_df['anomaly_score'].map({1: 'Normal', -1: 'Anomaly'})

            # 4. Display Summary Metrics
            anomalies = features_df[features_df['anomaly_score'] == -1]
            col1, col2 = st.columns(2)
            col1.metric("Total Pods Analyzed", len(features_df))
            col2.metric("Anomalies Detected", len(anomalies), delta_color="inverse")

            # 5. Visualization Chart
            st.subheader("📊 Anomaly Distribution Chart")
            
            # Show only anomalous pods for clarity
            anomaly_chart_data = anomalies.set_index('pod_name')[['error_count', 'warn_count', 'debug_count']]
            
            if not anomaly_chart_data.empty:
                fig, ax = plt.subplots(figsize=(14, max(8, len(anomalies) * 0.5)))
                anomaly_chart_data.plot(kind='barh', ax=ax, color=['#e74c3c', '#f39c12', '#3498db'])
                
                plt.title("Log Level Distribution by Anomalous Pods")
                plt.xlabel("Log Count")
                plt.ylabel("Pod Name")
                plt.tight_layout()
                st.pyplot(fig)
            else:
                # If no anomalies, show top pods by error count
                fig, ax = plt.subplots(figsize=(14, 10))
                top_pods = features_df.nlargest(15, 'error_count').set_index('pod_name')[['error_count', 'warn_count', 'debug_count']]
                top_pods.plot(kind='barh', ax=ax, color=['#e74c3c', '#f39c12', '#3498db'])
                
                plt.title("Top 15 Pods by Error Count")
                plt.xlabel("Log Count")
                plt.ylabel("Pod Name")
                plt.tight_layout()
                st.pyplot(fig)

            # 6. Detailed Table
            st.subheader("🚨 Detected Suspicious Patterns")
            if not anomalies.empty:
                st.dataframe(anomalies)
            else:
                st.success("No critical anomalies detected in this log batch.")
        else:
            st.error(f"Dataset must contain these columns: {required_cols}")
            st.info("Required columns: 'log_level' (ERROR, WARN, DEBUG, INFO) and 'pod_name'")
            st.info("The uploaded file contains: " + str(df.columns.tolist()))