import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

FEATURE_COLUMNS = [
    "Dur", "Pkts", "Bytes", "IAT", "IAT_Variance", "IAT_Std",
    "Bytes_Variance", "Bytes_Per_Packet", "Proto_esp", "Proto_icmp",
    "Proto_igmp", "Proto_ipv6", "Proto_ipv6-icmp", "Proto_ipx/spx",
    "Proto_pim", "Proto_rarp", "Proto_rtcp", "Proto_rtp", "Proto_tcp",
    "Proto_udp", "Proto_udt", "Proto_unas", "FlowDir_Reverse",
]
PROTOCOL_FEATURES = FEATURE_COLUMNS[8:22]
ALERT_THRESHOLD = 0.20

def extract_window_features(df_window):
    """Compute the exact 23 features expected by botnet_c2_detector.pkl."""
    if len(df_window) < 2:
        return None

    df_sorted = df_window.sort_values(by="timestamp_unix")
    timestamps = df_sorted["timestamp_unix"].to_numpy(dtype=np.float64)
    bytes_arr = df_sorted["bytes"].to_numpy(dtype=np.float64)
    pkts_arr = df_sorted["pkts"].to_numpy(dtype=np.float64)
    iats = np.diff(timestamps)
    total_packets = float(np.sum(pkts_arr))
    protocols = set(df_sorted["protocol"].astype(str).str.lower())
    features = {
        "Dur": float(timestamps[-1] - timestamps[0]),
        "Pkts": total_packets,
        "Bytes": float(np.sum(bytes_arr)),
        "IAT": float(np.mean(iats)),
        "IAT_Variance": float(np.var(iats)),
        "IAT_Std": float(np.std(iats)),
        "Bytes_Variance": float(np.var(bytes_arr)),
        "Bytes_Per_Packet": float(np.sum(bytes_arr) / total_packets) if total_packets else 0.0,
        "FlowDir_Reverse": float(df_sorted["flow_dir_reverse"].astype(bool).any()),
    }
    for feature in PROTOCOL_FEATURES:
        features[feature] = float(feature.removeprefix("Proto_").lower() in protocols)
    return {name: features[name] for name in FEATURE_COLUMNS}

def _first_column(df, names, default):
    for name in names:
        if name in df.columns:
            return df[name]
    return pd.Series(default, index=df.index)

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

    df["bytes"] = pd.to_numeric(_first_column(df, ["Bytes", "TotBytes", "bytes"], 0), errors="coerce").fillna(0)
    df["pkts"] = pd.to_numeric(_first_column(df, ["Pkts", "TotPkts", "pkts"], 0), errors="coerce").fillna(0)
    df["protocol"] = _first_column(df, ["Proto", "Protocol", "proto", "protocol"], "").fillna("")
    reverse = _first_column(df, ["FlowDir_Reverse", "flow_dir_reverse"], 0)
    df["flow_dir_reverse"] = pd.to_numeric(reverse, errors="coerce").fillna(0).astype(bool)

    # Ground truth mapping: 1 for Botnet, 0 for Normal/Background
    df["target"] = df["Label"].astype(str).apply(lambda x: 1 if "botnet" in x.lower() else 0)

    features_list = []
    labels = []

    # Group by conversation key (SrcAddr, DstAddr)
    for (src, dst), group in df.groupby(["SrcAddr", "DstAddr"]):
        if len(group) < 2:
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
    y_prob = rf_model.predict_proba(X_val)[:, 1]
    y_pred = (y_prob >= ALERT_THRESHOLD).astype(np.uint8)

    print("\nConfusion Matrix:")
    print(f"Threshold: {ALERT_THRESHOLD:.2f}")
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
    artifact_path = "botnet_c2_detector.pkl"
    joblib.dump(rf_model, artifact_path)
    print(f"\n[+] Successfully serialized Random Forest model to: {artifact_path}")

if __name__ == "__main__":
    main()