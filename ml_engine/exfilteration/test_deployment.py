import pandas as pd
from deployment import DataExfiltrationDetector

# 1. Initialize the detector
print("Initializing DataExfiltrationDetector...")
detector = DataExfiltrationDetector()
print(f"Loaded successfully! Threshold: {detector.threshold}")

# 2. Create a dummy test DataFrame simulating incoming network telemetry row
dummy_data = pd.DataFrame(
    {
        "dur": [0.123],
        "proto": ["tcp"],
        "service": ["http"],
        "state": ["CON"],
        "spkts": [10],
        "dpkts": [8],
        "sbytes": [500],
        "dbytes": [1200],
        "rate": [85.5],
    }
)

# 3. Run prediction
print("Running prediction on sample telemetry...")
results = detector.predict(dummy_data)

for res in results:
  print("\nPrediction Result:")
  print(f"  - Threat Status: {res['is_threat']}")
  print(f"  - Prediction Class: {res['prediction']} (0=Benign, 1=Attack/Exfil)")
  print(f"  - Confidence: {res['confidence']:.4f}")
  print(f"  - Evidence: {res['evidence']}")