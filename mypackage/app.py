import os

import streamlit as st
import numpy as np
import joblib
from feature_extraction import FeatureExtractor
from url_verification import URLVerification

# ========== Label Mapping (Multiclass) ==========
label_map = {
    0: "🟢 Benign",
    1: "🔴 Defacement",
    2: "🔴 Phishing",
    3: "🔴 Malware"
}

# ========== Model Paths ==========
model_files = {
    "Random Forest": "../models/rf_model.pkl",
    "XGBoost": "../models/xgb_c.pkl",
    "LightGBM": "../models/lgb.pkl",
}

# ========== Streamlit UI ==========
st.set_page_config(page_title="Malicious URL Classifier", page_icon="🔐")
st.title("🔐 URL Threat Classification")
st.write("Enter a URL to classify it as benign, phishing, malware, or defacement using multiple models.")

url_input = st.text_input("🔗 Enter a URL", "https://example.com")
if st.button("Classify URL"):
    verifier = URLVerification(url_input)
    if verifier.verify() is False:
        st.error("Invalid URL format. Please enter a valid URL.")
    else:
        # Feature Extraction
        extractor = FeatureExtractor()
        features = extractor.extract(url_input)
        
        # Load Models and Make Predictions
        predictions = {}
        for model_name, model_path in model_files.items():
            if os.path.exists(model_path):
                model, feature_names = joblib.load(model_path)
                features = np.array(features).reshape(1, -1)  # Reshape to ensure it's a 2D array for model input
                pred = model.predict(features)[0]
                predictions[model_name] = label_map.get(pred)
            else:
                predictions[model_name] = "Model not found"
        
        # Display Results
        st.subheader("Classification Results")
        for model_name, result in predictions.items():
            st.write(f"{model_name}: {result}")

