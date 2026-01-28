import streamlit as st
import joblib
import os
import pandas as pd
import re
import tldextract

# --- STEP 1: FIX IMPORTS ---
# We try to import from 'extract.py' directly. 
# If that fails, we try 'src.extract'.
try:
    from extract import get_features
except ImportError:
    try:
        from src.extract import get_features
    except ImportError:
        # Fallback: Define the function here if the file is missing
        def get_features(url):
            features = {
                'URLLength': len(url),
                'NoOfLettersInURL': sum(c.isalpha() for c in url),
                'NoOfDegitsInURL': sum(c.isdigit() for c in url),
                'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9]', url)),
            }
            return pd.DataFrame([features])

# --- STEP 2: FIX MODEL PATH ---
# This looks for the model in the current folder OR a 'models' subfolder
MODEL_NAME = "phishing_model.pkl"
if os.path.exists(MODEL_NAME):
    model_path = MODEL_NAME
elif os.path.exists(os.path.join("models", MODEL_NAME)):
    model_path = os.path.join("models", MODEL_NAME)
else:
    model_path = None

st.set_page_config(page_title="SOC Mini-Tool", page_icon="🛡️")

st.title("🛡️ Phishing URL Detector")

if model_path is None:
    st.error(f"❌ Could not find {MODEL_NAME}. Please make sure the file is uploaded to your GitHub repository.")
else:
    try:
        model = joblib.load(model_path)
        
        url_input = st.text_input("Enter URL to scan:", placeholder="https://secure-update-paypal.com")

        if st.button("Run Security Analysis"):
            if url_input:
                # Extract features
                features_df = get_features(url_input)
                
                # Match the 4 features your model was trained on
                training_features = ['URLLength', 'NoOfLettersInURL', 'NoOfDegitsInURL', 'NoOfOtherSpecialCharsInURL']
                input_data = features_df[training_features]
                
                # Prediction
                prediction = model.predict(input_data)[0]
                probability = model.predict_proba(input_data)[0][1]

                st.subheader("Analysis Result")
                if prediction == 1:
                    st.error(f"🚨 PHISHING DETECTED! Confidence: {probability*100:.1f}%")
                else:
                    st.success(f"✅ LEGITIMATE. Confidence: {(1-probability)*100:.1f}%")
    except Exception as e:
        st.error(f"An error occurred: {e}")
