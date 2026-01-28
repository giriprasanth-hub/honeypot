import pandas as pd
import numpy as np
import joblib
import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

MODEL_PATH = "ml_engine/scam_model.pkl"

class ScamDetector:
    def __init__(self):
        self.model = None
        self._load_or_train_model()

    def _load_or_train_model(self):
        """Loads existing model or trains a dummy one if missing."""
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            print("✅ Loaded trained Scam Model.")
        else:
            print("⚠️ No model found. Training a baseline model now...")
            self._train_baseline_model()

    def _train_baseline_model(self):
        """Trains a quick model on synthetic data."""
        data = [
            ("Your account is locked. Verify KYC now.", 1),
            ("Click this link to update your PAN card.", 1),
            ("You have won a lottery! Claim prize.", 1),
            ("Urgent: electricity bill unpaid. Power disconnection.", 1),
            ("Hey, are we still meeting for lunch?", 0),
            ("Your OTP for login is 1234. Do not share.", 0),
            ("Mom called, she wants you to buy milk.", 0),
            ("Transaction successful: ₹500 paid to Zomato.", 0)
        ]
        df = pd.DataFrame(data, columns=["text", "label"])
        
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 2))),
            ('clf', RandomForestClassifier(n_estimators=100))
        ])
        
        self.model.fit(df['text'], df['label'])
        joblib.dump(self.model, MODEL_PATH)
        print("✅ Baseline model trained and saved.")

    def predict(self, message: str):
        """Returns: is_scam (bool), confidence (float), scam_type (str)"""
        
        # 1. Heuristic Check
        red_flags = [
            r"kyc", r"verify", r"block", r"suspend", r"lottery", 
            r"winner", r"claim", r"urgent", r"disconnect"
        ]
        heuristic_score = 0
        for pattern in red_flags:
            if re.search(pattern, message.lower()):
                heuristic_score += 0.2
        
        # 2. ML Prediction
        ml_prob = self.model.predict_proba([message])[0][1]
        
        # 3. Ensemble Score
        final_score = min(1.0, (ml_prob * 0.7) + (heuristic_score * 0.3))
        
        is_scam = final_score > 0.5
        
        # Determine Type
        scam_type = "clean"
        if is_scam:
            if "kyc" in message.lower() or "pan" in message.lower():
                scam_type = "kyc_phishing"
            elif "winner" in message.lower():
                scam_type = "lottery_scam"
            elif "bill" in message.lower():
                scam_type = "utility_scam"
            else:
                scam_type = "general_phishing"

        return {
            "is_scam": bool(is_scam),
            "confidence": float(round(final_score, 4)),  # <--- FIXED: Explicit float cast
            "scam_type": scam_type
        }

# Singleton instance
detector = ScamDetector()