import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# Note: Ensure df_unsw is loaded here before running, e.g.:
# df_unsw = pd.read_csv("ml_engine/exfilteration/data/your_dataset.csv")

# 1. Clean and Prepare Features
df_clean = df_unsw.copy()
if "id" in df_clean.columns:
  df_clean = df_clean.drop(columns=["id"])

if "attack_cat" in df_clean.columns:
  y = df_clean["label"]
  X = df_clean.drop(columns=["label", "attack_cat"])
else:
  y = df_clean["label"]
  X = df_clean.drop(columns=["label"])

# One-hot encode string/categorical columns (proto, service, state)
X = pd.get_dummies(X, drop_first=True)

# Coerce everything to numeric and drop invalid entries
for col in X.columns:
  X[col] = pd.to_numeric(X[col], errors="coerce")

X = X.replace([np.inf, -np.inf], np.nan).dropna()
y = y.loc[X.index]

print(f"Processed Feature Matrix Shape: {X.shape}")

# 2. Stratified Split
X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

pos_weight = (y_tr == 0).sum() / ((y_tr == 1).sum() + 1e-5)

# 3. High-Capacity XGBoost Engine
xgb_unsw = XGBClassifier(
    n_estimators=400,
    max_depth=10,
    learning_rate=0.03,
    subsample=0.85,
    colsample_bytree=0.85,
    scale_pos_weight=pos_weight * 0.3,
    random_state=42,
    n_jobs=-1,
)

print("\nTraining XGBoost on UNSW-NB15...")
xgb_unsw.fit(X_tr, y_tr)

# 4. Evaluation & Threshold Optimization
y_probs = xgb_unsw.predict_proba(X_te)[:, 1]
auc_score = roc_auc_score(y_te, y_probs)
print(f"\nUNSW-NB15 Model ROC-AUC Score: {auc_score:.4f}")

print(
    f"\n{'Threshold':<12}{'Precision (1)':<16}{'Recall (1)':<14}{'F1 (1)':<10}{'Accuracy':<10}"
)
print("-" * 62)

best_f1 = 0
best_t = 0.5

for t in [0.20, 0.30, 0.40, 0.50, 0.60, 0.70]:
  preds = (y_probs >= t).astype(int)
  p = np.sum((preds == 1) & (y_te == 1)) / (np.sum(preds == 1) + 1e-10)
  r = np.sum((preds == 1) & (y_te == 1)) / (np.sum(y_te == 1) + 1e-10)
  f1 = 2 * (p * r) / (p + r + 1e-10)
  acc = accuracy_score(y_te, preds)
  if f1 > best_f1:
    best_f1 = f1
    best_t = t
  print(f"{t:<12.2f}{p:<16.4f}{r:<14.4f}{f1:<10.4f}{acc:<10.4f}")

print(f"\nOptimal Threshold: {best_t} with F1-Score: {best_f1:.4f}")

# 5. Save the Model Bundle for Production Deployment
artifact = {
    "model": xgb_unsw,
    "features": list(X.columns),
    "threshold": float(best_t),
}

model_path = "ml_engine/exfilteration/exfiltration_model.pkl"
joblib.dump(artifact, model_path)
print(f"\nSuccessfully saved production model bundle to: {model_path}")