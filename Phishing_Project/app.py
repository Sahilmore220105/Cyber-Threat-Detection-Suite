import streamlit as st
import joblib
import os
import pandas as pd
# Changed from 'from src.extract' to 'import extract' 
# or 'from extract' based on your file structure
try:
    from extract import get_features
except ImportError:
    from src.extract import get_features

# Check both the root and models folder for the pickle file
MODEL_PATH = "phishing_model.pkl"
ALT_MODEL_PATH = "models/phishing_model.pkl"

st.set_page_config(page_title="SOC Mini-Tool", page_icon="🛡️")

st.title("🛡️ Phishing URL Detector")
st.info("This tool uses Machine Learning to analyze URL patterns for potential threats.")

# Robust model loading logic
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
elif os.path.exists(ALT_MODEL_PATH):
    model = joblib.load(ALT_MODEL_PATH)

if model is None:
    st.error("Model file not found! Please ensure 'phishing_model.pkl' is in the repository.")
else:
    url_input = st.text_input("Enter URL to scan:", placeholder="https://secure-update-paypal.com")

    if st.button("Run Security Analysis"):
        if url_input:
            # 1. Extract features
            features_df = get_features(url_input)
            
            # 2. Match the features used during training
            training_features = ['URLLength', 'NoOfLettersInURL', 'NoOfDegitsInURL', 'NoOfOtherSpecialCharsInURL']
            
            # Ensure features exist in the dataframe
            try:
                input_data = features_df[training_features]
                
                # 3. Prediction
                prediction = model.predict(input_data)[0]
                probability = model.predict_proba(input_data)[0][1]

                # 4. Results UI
                st.subheader("Analysis Result")
                if prediction == 1:
                    st.error(f"🚨 PHISHING DETECTED! Confidence: {probability*100:.1f}%")
                    st.warning("Top Suspicious Factors: Uncommon special characters, unusual length.")
                else:
                    st.success(f"✅ LEGITIMATE. Confidence: {(1-probability)*100:.1f}%")
                    st.info("This URL matches standard safe patterns.")
            except KeyError as e:
                st.error(f"Feature extraction error: Missing columns {e}")
