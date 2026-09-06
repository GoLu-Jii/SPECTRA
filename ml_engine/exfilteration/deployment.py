# ml_engine/exfilteration/deployment.py

import os
import joblib
import pandas as pd
import numpy as np

class DataExfiltrationDetector:
    def __init__(self, model_path=None):
        if model_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, "threat_06_unsw_specialized_model (1).pkl")
        
        artifact = joblib.load(model_path)
        
        # Handle dictionary bundle vs raw estimator
        if isinstance(artifact, dict):
            self.model = artifact.get("model")
            self.expected_features = artifact.get("features", [])
            self.threshold = artifact.get("threshold", 0.5)
        else:
            self.model = artifact
            self.expected_features = []
            self.threshold = 0.5

    def preprocess(self, data):
        if isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data)
        elif isinstance(data, pd.DataFrame):
            df = data.copy()
        else:
            raise ValueError("Unsupported input format. Provide dict, list of dicts, or DataFrame.")

        # Drop target or identifier columns if accidentally passed
        for col in ['Label', 'is_exfil', 'id', 'flow_id']:
            if col in df.columns:
                df = df.drop(columns=[col])

        # Batched one-hot encoding to mirror training pipeline
        df = pd.get_dummies(df)

        # Align features to what the model expects if recorded
        if self.expected_features:
            for feat in self.expected_features:
                if feat not in df.columns:
                    df[feat] = 0
            df = df[self.expected_features]

        # Sanitize infinities and NaNs
        df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
        return df

    def predict(self, data):
        df_processed = self.preprocess(data)
        
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(df_processed)
            scores = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
        else:
            scores = self.model.predict(df_processed)
            
        predictions = (scores >= self.threshold).astype(int)
        
        results = []
        for pred, score in zip(predictions, scores):
            results.append({
                "prediction": int(pred),
                "confidence": float(score),
                "label": "exfiltration" if pred == 1 else "benign"
            })
        return results

    def health_check(self):
        return {"status": "healthy", "model_loaded": self.model is not None}