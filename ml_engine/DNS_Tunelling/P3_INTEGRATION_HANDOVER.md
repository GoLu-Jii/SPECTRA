# DNS tunnelling detector handover

## Files

- Detector wrapper: `dns_tunnelling_detector.py`
- Existing model path: `dns_tunnelling_xgb_model.pkl`
- Feature schema: `dns_tunnelling_schema.json`
- Training source: `DNS_tunnelling.ipynb`

The restored model file is a 277 KB XGBoost artifact and is the model saved by the notebook's `joblib.dump(xgb_dns, ...)` cell.

## Inference contract

The input must already be one aggregated flow/DoH statistical record. The exact feature order is the `expected_features` list in `dns_tunnelling_schema.json`: `Duration`, `FlowBytesSent`, `FlowSentRate`, `FlowBytesReceived`, `FlowReceivedRate`, the 8 packet-length statistics, the 8 packet-time statistics, and the 8 response-time statistics. The complete list is implemented as `FEATURE_ORDER` in `dns_tunnelling_detector.py`.

Training dropped `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `TimeStamp`, and any `Label` column. It filled missing feature values with zero. No scaling, rolling calculation, event grouping, or feature encoding was implemented. The notebook expects the 29 statistical values to already exist in the input CSV; it does not provide packet-to-statistics aggregation logic.

## Prediction and evidence

`0` means benign DoH and `1` means malicious DNS tunnelling. Confidence is `predict_proba(...)[0][1]`. The classification threshold is `0.50`. Supporting evidence should contain the exact 29 input feature values; the wrapper returns all of them plus the prediction label.

No minimum event count, grouping key, chronological window, environment variables, or final commit hash was recorded in the notebook. This is a per-aggregated-record detector, not a streaming window manager.

## Handover status

The original model, schema, notebook, and wrapper are restored. The upstream packet-to-statistics extractor and original training CSVs are still not present in this workspace, so retraining cannot be reproduced until those CSVs are supplied.