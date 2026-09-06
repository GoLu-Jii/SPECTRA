import os
import joblib
import numpy as np
import pandas as pd
from scipy.stats import entropy
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

FEATURE_COLUMNS = [
    "iat_mean",
    "iat_std",
    "iat_cv",
    "flow_count",
    "bytes_mean",
    "bytes_std",
    "pkts_mean",
    "dest_port_entropy"
]

def extract_window_features(df_window):
    """Computes the 8 target behavioral features from a conversational flow window."""
    if len(df_window) < 4:
        return None

    # Chronological sort
    df_sorted = df_window.sort_values(by="timestamp_unix")
    timestamps = df_sorted["timestamp_unix"].to_numpy(dtype=np.float64)
    bytes_arr = df_sorted["TotBytes"].to_numpy(dtype=np.float64)
    pkts_arr = df_sorted["TotPkts"].to_numpy(dtype=np.float64)
    ports = df_sorted["Dport"].tolist()

    # Inter-Arrival Time (IAT)
    iats = np.diff(timestamps)
    iat_mean = float(np.mean(iats))
    iat_std = float(np.std(iats))
    iat_cv = float(iat_std / (iat_mean + 1e-6))

    # Destination Port Entropy
    port_counts = list(Counter(ports).values())
    port_ent = float(entropy(port_counts)) if len(port_counts) > 0 else 0.0

    return {
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_cv": iat_cv,
        "flow_count": len(df_sorted),
        "bytes_mean": float(np.mean(bytes_arr)),
        "bytes_std": float(np.std(bytes_arr)),
        "pkts_mean": float(np.mean(pkts_arr)),
        "dest_port_entropy": port_ent
    }

def prepare_dataset(file_path, window_duration_seconds=300):
    """Parses CTU-13 NetFlow logs and aggregates them into rolling conversational windows."""
    print(f"[*] Ingesting: {file_path}")
    df = pd.read_csv(file_path)

    # Clean whitespace in column headers
    df.columns = [c.strip() for c in df.columns]

    # Convert timestamps to float epoch seconds
    if "StartTime" in df.columns:
        df["timestamp_unix"] = pd.to_datetime(df["StartTime"]).astype("int64") // 10**9
    elif "StartTimeUnix" in df.columns:
        df["timestamp_unix"] = pd.to_numeric(df["StartTimeUnix"], errors="coerce")
    else:
        # Fallback for synthetic/relative sequence index
        df["timestamp_unix"] = np.arange(len(df), dtype=np.float64)

    # Cast numeric attributes
    df["TotBytes"] = pd.to_numeric(df.get("TotBytes", df.get("bytes", 0)), errors="coerce").fillna(0)
    df["TotPkts"] = pd.to_numeric(df.get("TotPkts", df.get("pkts", 1)), errors="coerce").fillna(1)
    df["Dport"] = df.get("Dport", df.get("dst_port", 0)).fillna(0)

    # Ground truth mapping: 1 for Botnet, 0 for Normal/Background
    df["target"] = df["Label"].astype(str).apply(lambda x: 1 if "botnet" in x.lower() else 0)

    features_list = []
    labels = []

    # Group by conversation key (SrcAddr, DstAddr)
    for (src, dst), group in df.groupby(["SrcAddr", "DstAddr"]):
        if len(group) < 4:
            continue

        group = group.sort_values(by="timestamp_unix")
        start_t = group["timestamp_unix"].iloc[0]
        end_t = group["timestamp_unix"].iloc[-1]

        current_t = start_t
        while current_t < end_t:
            sub = group[
                (group["timestamp_unix"] >= current_t) &
                (group["timestamp_unix"] < current_t + window_duration_seconds)
            ]
            feats = extract_window_features(sub)
            if feats is not None:
                features_list.append(feats)
                labels.append(int(sub["target"].max()))
            current_t += (window_duration_seconds / 2)  # 50% overlap step

    X = pd.DataFrame(features_list)[FEATURE_COLUMNS]
    y = np.array(labels, dtype=np.int32)
    return X, y

def main():
    train_path = "/content/drive/MyDrive/Hackathon_Data/botnet_42.2format"
    val_path   = "/content/drive/MyDrive/Hackathon_Data/botnet_50.2format"

    # Step 1: Feature Extraction
    print("--- Phase 1: Feature Extraction ---")
    X_train, y_train = prepare_dataset(train_path)
    print(f"Train Dataset: {len(X_train)} windows | Botnet Windows: {np.sum(y_train)}")

    X_val, y_val = prepare_dataset(val_path)
    print(f"Validation Dataset: {len(X_val)} windows | Botnet Windows: {np.sum(y_val)}")

    # Step 2: Model Training
    print("\n--- Phase 2: Training Balanced Random Forest ---")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=8,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Step 3: Out-of-Distribution Validation
    print("\n--- Phase 3: Out-of-Distribution Validation (Capture 50) ---")
    y_pred = rf_model.predict(X_val)
    y_prob = rf_model.predict_proba(X_val)[:, 1]

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_val, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_val, y_pred, digits=4))

    roc = roc_auc_score(y_val, y_prob)
    print(f"ROC-AUC Score: {roc:.4f}")

    # Feature Importance Inspection
    print("\nFeature Importances:")
    importances = rf_model.feature_importances_
    for col, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True):
        print(f"  - {col:<20}: {imp:.4f}")

    # Step 4: Export Artifact
    os.makedirs("models", exist_ok=True)
    artifact_path = "models/c2_beaconing_rf.pkl"
    joblib.dump(rf_model, artifact_path)
    print(f"\n[+] Successfully serialized Random Forest model to: {artifact_path}")

if __name__ == "__main__":
    main()