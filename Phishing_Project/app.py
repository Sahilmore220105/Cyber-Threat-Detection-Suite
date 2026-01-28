import streamlit as st
import joblib
import os
from src.extract import get_features

# Load the trained model from the models folder
MODEL_PATH = "models/phishing_model.pkl"

st.set_page_config(page_title="SOC Mini-Tool", page_icon="🛡️")

st.title("🛡️ Phishing URL Detector")
st.info("This tool uses Machine Learning to analyze URL patterns for potential threats.")

# Check if model exists
if not os.path.exists(MODEL_PATH):
    st.error("Model file not found! Please run 'python src/train.py' first.")
else:
    model = joblib.load(MODEL_PATH)
    
    url_input = st.text_input("Enter URL to scan:", placeholder="https://secure-update-paypal.com")

    if st.button("Run Security Analysis"):
        if url_input:
            # 1. Extract features using our src/extract.py logic
            features_df = get_features(url_input)
            
            # 2. Match the features used during training
            training_features = ['URLLength', 'NoOfLettersInURL', 'NoOfDegitsInURL', 'NoOfOtherSpecialCharsInURL']
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
        else:
            st.warning("Please enter a URL to analyze.")
