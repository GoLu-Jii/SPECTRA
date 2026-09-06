# DNS tunnelling detector handover

## Files

- Detector wrapper: `dns_tunnelling_detector.py`
- Existing model path: `dns_tunnelling_xgb_model.pkl`
- Feature schema: `dns_tunnelling_schema.json`
- Training source: `DNS_tunnelling.ipynb`

The existing model file in this checkout is only 56 bytes and cannot be loaded as a joblib model. Obtain the real artifact from the producing branch or artifact store.

## Inference contract

The input must already be one aggregated flow/DoH statistical record. The exact feature order is the `expected_features` list in `dns_tunnelling_schema.json`: `Duration`, `FlowBytesSent`, `FlowSentRate`, `FlowBytesReceived`, `FlowReceivedRate`, the 8 packet-length statistics, the 8 packet-time statistics, and the 8 response-time statistics. The complete list is implemented as `FEATURE_ORDER` in `dns_tunnelling_detector.py`.

Training dropped `SourceIP`, `DestinationIP`, `SourcePort`, `DestinationPort`, `TimeStamp`, and any `Label` column. It filled missing feature values with zero. No scaling, rolling calculation, event grouping, or feature encoding was implemented. The notebook does not specify how the 29 statistical values are calculated from packets, so P3 must supply that upstream aggregation or obtain the feature extractor from the producing team.

## Prediction and evidence

`0` means benign DoH and `1` means malicious DNS tunnelling. Confidence is `predict_proba(...)[0][1]`. The classification threshold is `0.50`. Supporting evidence should contain the exact 29 input feature values; the wrapper returns all of them plus the prediction label.

No minimum event count, grouping key, chronological window, environment variables, or final commit hash was recorded in the notebook. This is a per-aggregated-record detector, not a streaming window manager.

## Handover status

The notebook produced a model and schema export conceptually, but this checkout does not contain a loadable model artifact or the upstream statistical feature extractor. Do not integrate until both are supplied and validated against the trained column order.