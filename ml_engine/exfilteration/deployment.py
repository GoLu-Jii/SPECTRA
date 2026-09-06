import joblib
import numpy as np
import pandas as pd


class DataExfiltrationDetector:

  def __init__(
      self,
      model_path: str = (
          "ml_engine/exfilteration/threat_06_unsw_specialized_model (1).pkl"
      ),
  ):
    self.model_path = model_path
    self.model = None
    self.expected_features = []
    self.threshold = 0.5
    self.load_artifact()

  def load_artifact(self):
    """Loads the trained model bundle, feature list, and calibrated threshold."""
    artifact = joblib.load(self.model_path)
    if isinstance(artifact, dict):
      self.model = artifact.get("model")
      self.expected_features = artifact.get("features", [])
      self.threshold = artifact.get("threshold", 0.5)
    else:
      self.model = artifact

  def preprocess(self, raw_df: pd.DataFrame) -> pd.DataFrame:
    """Applies exact one-hot encoding, cleaning, and batched schema alignment."""
    df_clean = raw_df.copy()
    if "id" in df_clean.columns:
      df_clean = df_clean.drop(columns=["id"])
    if "attack_cat" in df_clean.columns:
      df_clean = df_clean.drop(columns=["attack_cat"], errors="ignore")
    if "label" in df_clean.columns:
      df_clean = df_clean.drop(columns=["label"], errors="ignore")

    # One-hot encode string columns
    df_encoded = pd.get_dummies(df_clean, drop_first=True)

    # Safe numeric coercion
    for col in df_encoded.columns:
      df_encoded[col] = pd.to_numeric(df_encoded[col], errors="coerce")
    df_encoded = df_encoded.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # Batched alignment to eliminate fragmentation warnings
    if self.expected_features:
      aligned_data = {}
      for col in self.expected_features:
        if col in df_encoded.columns:
          aligned_data[col] = df_encoded[col]
        else:
          aligned_data[col] = 0.0
      df_encoded = pd.DataFrame(aligned_data, index=df_encoded.index)
      df_encoded = df_encoded[self.expected_features]

    return df_encoded

  def predict(self, raw_data: pd.DataFrame) -> list[dict]:
    """Runs streaming inference and generates structured alert evidence."""
    X_processed = self.preprocess(raw_data)
    probabilities = self.model.predict_proba(X_processed)[:, 1]
    predictions = (probabilities >= self.threshold).astype(int)

    results = []
    for i, pred in enumerate(predictions):
      conf = float(probabilities[i])
      result = {
          "prediction": int(pred),  # 0 = Benign, 1 = Exfiltration/Attack
          "confidence": conf,
          "is_threat": bool(pred == 1),
          "evidence": {
              "model_probability": conf,
              "threshold_used": self.threshold,
              "top_contributing_features": (
                  X_processed.iloc[i].nlargest(5).to_dict()
              ),
          },
      }
      results.append(result)

    return results