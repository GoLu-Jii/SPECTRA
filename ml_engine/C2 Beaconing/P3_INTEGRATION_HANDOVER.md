# C2 beaconing detector handover

## Files

- Detector: `c2_beaconing_detector.py`
- Training/export source: `train_c2_model.py`
- Intended training artifact: `botnet_c2_detector.pkl`
- Artifact currently present in this checkout: `botnet_c2_detector.pkl`

The saved artifact is a 23-feature Random Forest model. The trainer now exports the same filename and schema as the wrapper.

## Inference contract

Input is a chronological list of at least 2 flow dictionaries for one `(SrcIP, DstIP)` conversation. Required keys are `start_time_unix`; `bytes`, `pkts`, protocol, and reverse-direction fields are supported with defaults. The wrapper sorts by `start_time_unix` before calculating features.

The exact model feature order is:

`Dur`, `Pkts`, `Bytes`, `IAT`, `IAT_Variance`, `IAT_Std`, `Bytes_Variance`, `Bytes_Per_Packet`, `Proto_esp`, `Proto_icmp`, `Proto_igmp`, `Proto_ipv6`, `Proto_ipv6-icmp`, `Proto_ipx/spx`, `Proto_pim`, `Proto_rarp`, `Proto_rtcp`, `Proto_rtp`, `Proto_tcp`, `Proto_udp`, `Proto_udt`, `Proto_unas`, `FlowDir_Reverse`.

IAT is calculated from consecutive sorted timestamps. `Dur`, `Pkts`, and `Bytes` are window totals; IAT and byte variance use population variance. Protocol columns are one-hot indicators and `FlowDir_Reverse` is a boolean indicator. The training pipeline uses 300-second windows with a 150-second step and groups by `(SrcAddr, DstAddr)`; windows with fewer than 2 flows are skipped. P3 must preserve chronological ordering before windowing.

No scaling or encoding is applied. Missing bytes default to zero, missing packet counts default to one, and missing destination ports default to zero in the wrapper.

## Prediction and evidence

`0` means normal and `1` means botnet C2. Confidence is the Random Forest malicious-class probability. The integration and training evaluation threshold is `0.20`.

Evidence returned by the wrapper includes mean IAT, IAT variance, IAT coefficient of variation, flow count, window duration, and a textual timing summary. P3 should also retain the source/destination conversation key used for grouping.

No environment variables or final Git commit hash were recorded in the implementation. The training captures remain configured as `/content/drive/MyDrive/Hackathon_Data/botnet_42.2format` and `botnet_50.2format`.