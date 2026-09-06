# C2 beaconing detector handover

## Files

- Detector: `c2_beaconing_detector.py`
- Training/export source: `train_c2_model.py`
- Intended training artifact: `models/c2_beaconing_rf.pkl`
- Artifact currently present in this checkout: `botnet_c2_detector.pkl`

The present artifact is only 13 bytes and cannot be loaded as a joblib model. Obtain the real Random Forest artifact before integration. The wrapper's default path also points to `models/c2_beaconing_rf.pkl`, not the root-level artifact.

## Inference contract

Input is a chronological list of at least 4 flow dictionaries for one `(SrcIP, DstIP)` conversation. Required keys are `start_time_unix`, `bytes`, `pkts`, and `dst_port`. The wrapper sorts by `start_time_unix` before calculating features.

The exact model feature order is:

`iat_mean`, `iat_std`, `iat_cv`, `flow_count`, `bytes_mean`, `bytes_std`, `pkts_mean`, `dest_port_entropy`.

IAT is the difference between consecutive sorted timestamps. Port entropy uses the Shannon entropy of destination-port counts. The training pipeline uses 300-second windows with a 150-second step and groups by `(SrcAddr, DstAddr)`; windows with fewer than 4 flows are skipped. P3 must preserve chronological ordering before windowing.

No scaling or encoding is applied. Missing bytes default to zero, missing packet counts default to one, and missing destination ports default to zero in the wrapper.

## Prediction and evidence

`0` means non-beaconing/benign and `1` means botnet C2 beaconing. Confidence is the Random Forest malicious-class probability. The detector default alert threshold is `0.85`; the training notebook itself did not tune or persist a threshold.

Evidence returned by the wrapper includes mean IAT, IAT variance, IAT coefficient of variation, flow count, window duration, and a textual timing summary. P3 should also retain the source/destination conversation key used for grouping.

No environment variables or final Git commit hash were recorded in the implementation. The real artifact and its producing commit are required for a complete handover.