import streamlit as st
import joblib
import os
import pandas as pd
import re

# --- 1. SAFE FEATURE EXTRACTION IMPORT ---
# This ensures the app doesn't crash if 'src' folder is missing
try:
    from extract import get_features
except ImportError:
    try:
        from src.extract import get_features
    except ImportError:
        # Emergency fallback logic if extract.py is missing entirely
        def get_features(url):
            features = {
                'URLLength': len(url),
                'NoOfLettersInURL': sum(c.isalpha() for c in url),
                'NoOfDegitsInURL': sum(c.isdigit() for c in url),
                'NoOfOtherSpecialCharsInURL': len(re.findall(r'[^a-zA-Z0-9]', url)),
            }
            return pd.DataFrame([features])

# --- 2. SAFE MODEL LOADING ---
# Checks both root and 'models/' folder
MODEL_NAME = "phishing_model.pkl"
model_path = None

if os.path.exists(MODEL_NAME):
    model_path = MODEL_NAME
elif os.path.exists(os.path.join("models", MODEL_NAME)):
    model_path = os.path.join("models", MODEL_NAME)

# --- 3. STREAMLIT UI ---
st.set_page_config(page_title="SOC Mini-Tool", page_icon="🛡️")

st.title("🛡️ Phishing URL Detector")
st.info("This tool uses Machine Learning to analyze URL patterns for potential threats.")

if model_path is None:
    st.error(f"❌ Model file '{MODEL_NAME}' not found! Please ensure it is uploaded to GitHub.")
else:
    # Load the model once
    model = joblib.load(model_path)
    
    url_input = st.text_input("Enter URL to scan:", placeholder="https://secure-update-paypal.com")

    if st.button("Run Security Analysis"):
        if url_input:
            try:
                # 1. Extract features
                features_df = get_features(url_input)
                
                # 2. Match the 4 features used during training
                training_features = ['URLLength', 'NoOfLettersInURL', 'NoOfDegitsInURL', 'NoOfOtherSpecialCharsInURL']
                input_data = features_df[training_features]
                
                # 3. Prediction
                prediction = model.predict(input_data)[0]
                probability = model.predict_proba(input_data)[0][1]

                # 4. Results UI
                st.subheader("Analysis Result")
                if prediction == 1:
                    st.error(f"🚨 PHISHING DETECTED! Confidence: {probability*100:.1f}%")
                    st.warning("Suspicious Factors: Unusual character count or URL structure.")
                else:
                    st.success(f"✅ LEGITIMATE. Confidence: {(1-probability)*100:.1f}%")
                    st.info("This URL follows common patterns for safe websites.")
            
            except Exception as e:
                st.error(f"Analysis failed: {e}")
        else:
            st.warning("Please enter a URL to analyze.")
