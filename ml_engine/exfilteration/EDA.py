# UNSW-NB15 EDA + ML TRAINING + EVALUATION

from google.colab import drive
drive.mount('/content/drive')

import os
import joblib
import pandas as pd
import numpy as np

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

# ============================================================
# PATHS
# ============================================================

TRAIN_PATH = "/content/drive/MyDrive/Colab Notebooks/threat_6/UNSW_NB15_synthetic_train_250k.csv"
TEST_PATH = "/content/drive/MyDrive/Colab Notebooks/threat_6/UNSW_NB15_synthetic_test_250k.csv"
MODEL_PATH = "/content/drive/MyDrive/Colab Notebooks/threat_6/rf_network_attack_detector_compact.pkl"
IMPORTANCE_PATH = "/content/drive/MyDrive/Colab Notebooks/threat_6/feature_importance.csv"

# ============================================================
# 1. LOAD TRAINING DATA
# ============================================================

train_df = pd.read_csv(TRAIN_PATH)

print("=" * 70)
print("DATASET EDA")
print("=" * 70)

print("Dataset shape:", train_df.shape)

print("\nColumns:")
print(train_df.columns.tolist())

print("\nMissing values:", train_df.isnull().sum().sum())
print("Duplicate rows:", train_df.duplicated().sum())

print("\nLabel distribution:")
print(train_df["label"].value_counts())

print("\nLabel percentage:")
print(train_df["label"].value_counts(normalize=True) * 100)

print("\nAttack categories:")
print(train_df["attack_cat"].value_counts())

print("\nData types:")
print(train_df.dtypes)

print("\nCategorical columns:")
print(train_df.select_dtypes(include="object").columns.tolist())

# ============================================================
# 2. MODEL FEATURES
# ============================================================

DROP_COLUMNS = ["id", "attack_cat", "label"]

X_train = train_df.drop(columns=DROP_COLUMNS)
y_train = train_df["label"]

categorical_features = ["proto", "service", "state"]

numerical_features = [
    col for col in X_train.columns
    if col not in categorical_features
]

print("\n" + "=" * 70)
print("MODEL INPUT")
print("=" * 70)

print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)
print("Categorical features:", categorical_features)
print("Numerical features:", len(numerical_features))
print("Total model features:", len(X_train.columns))

# ============================================================
# 3. PREPROCESSING
# ============================================================

preprocessor = ColumnTransformer(
    transformers=[
        (
            "categorical",
            OneHotEncoder(
                handle_unknown="ignore",
                sparse_output=True
            ),
            categorical_features
        ),
        (
            "numerical",
            "passthrough",
            numerical_features
        )
    ]
)

print("\nPreprocessor created successfully.")

# ============================================================
# 4. COMPACT RANDOM FOREST
# ============================================================

rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced_subsample",
    random_state=42,
    n_jobs=-1
)

rf_pipeline = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        ("classifier", rf_model)
    ]
)

print("Compact Random Forest pipeline created.")

# ============================================================
# 5. TRAIN
# ============================================================

print("\n" + "=" * 70)
print("MODEL TRAINING")
print("=" * 70)

print("Training Random Forest...")
rf_pipeline.fit(X_train, y_train)
print("Training completed.")

# ============================================================
# 6. FEATURE IMPORTANCE
# ============================================================

feature_importances = (
    rf_pipeline.named_steps["classifier"].feature_importances_
)

onehot_features = (
    rf_pipeline
    .named_steps["preprocessor"]
    .named_transformers_["categorical"]
    .get_feature_names_out(categorical_features)
)

all_feature_names = list(onehot_features) + numerical_features

feature_importance_df = pd.DataFrame({
    "feature": all_feature_names,
    "importance": feature_importances
}).sort_values(
    by="importance",
    ascending=False
)

print("\n" + "=" * 70)
print("TOP 20 FEATURE IMPORTANCES")
print("=" * 70)

print(feature_importance_df.head(20).to_string(index=False))

feature_importance_df.to_csv(
    IMPORTANCE_PATH,
    index=False
)

print("\nFeature importance saved:")
print(IMPORTANCE_PATH)

# ============================================================
# 7. LOAD TEST DATA
# ============================================================

test_df = pd.read_csv(TEST_PATH)

print("\n" + "=" * 70)
print("TEST DATASET")
print("=" * 70)

print("Test dataset shape:", test_df.shape)
print("Number of columns:", len(test_df.columns))

X_test = test_df.drop(
    columns=["id", "attack_cat", "label"]
)

y_test = test_df["label"]

print("X_test shape:", X_test.shape)
print("y_test shape:", y_test.shape)

# ============================================================
# 8. PREDICTIONS
# ============================================================

print("\n" + "=" * 70)
print("PREDICTIONS")
print("=" * 70)

print("Generating predictions...")

y_pred = rf_pipeline.predict(X_test)
y_prob = rf_pipeline.predict_proba(X_test)[:, 1]

print("Predictions completed.")

# ============================================================
# 9. EVALUATION
# ============================================================

print("\n" + "=" * 70)
print("UNSW-NB15 SYNTHETIC 250K TEST RESULTS")
print("=" * 70)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score : {f1_score(y_test, y_pred):.4f}")
print(f"ROC-AUC  : {roc_auc_score(y_test, y_prob):.4f}")

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Normal", "Attack"]
    )
)

# ============================================================
# 10. SAVE COMPACT MODEL
# ============================================================

print("\n" + "=" * 70)
print("SAVING COMPACT MODEL")
print("=" * 70)

joblib.dump(
    rf_pipeline,
    MODEL_PATH,
    compress=3
)

size_mb = os.path.getsize(MODEL_PATH) / (1024 * 1024)

print("Model saved successfully!")
print("Model path:", MODEL_PATH)
print(f"Model size: {size_mb:.2f} MB")

if size_mb <= 100:
    print("PASS: Model is <= 100 MB")
else:
    print("WARNING: Model is > 100 MB")

# ============================================================
# 11. VERIFY MODEL
# ============================================================

loaded_model = joblib.load(MODEL_PATH)

print("\nModel loaded successfully!")
print("Model type:", type(loaded_model))

# ============================================================
# 12. FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("FINAL SUMMARY")
print("=" * 70)

print("Training rows:", len(train_df))
print("Test rows:", len(test_df))
print("Model input features:", X_train.shape[1])
print("Categorical features:", len(categorical_features))
print("Numerical features:", len(numerical_features))
print(f"Model size: {size_mb:.2f} MB")
print("EDA + training + evaluation completed.")
