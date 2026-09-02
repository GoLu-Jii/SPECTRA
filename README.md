# SPECTRA

netspectra-sih/
├── docker-compose.yml           # Boots the backend, frontend, and log ingester
├── README.md                    # Setup instructions for the judges
│
├── data_and_demo/               # P4 & P6: Testing and presentation assets
│   ├── demo_traffic.pcap        # The exact PCAP to replay for the final pitch
│   ├── mock_alerts.json         # Static JSON so P5 can build UI on Day 1
│   └── zeek_logs/               # Live output directory where ingestion drops files
│
├── ml_engine/                   # P1 & P2: Six isolated ML workspaces
│   ├── interface.py             # The vital contract (BaseThreatDetector)
│   ├── ddos/                    # P1's workspace
│   │   ├── train_ddos.ipynb     # Offline training notebook
│   │   ├── detector.py          # Wrapper class loading the model (implements interface.py)
│   │   └── ddos_model.pkl       # Serialized weights
│   ├── recon/                   # P1's workspace
│   ├── exfiltration/            # P1's workspace
│   ├── beaconing/               # P2's workspace
│   ├── dns_tunnelling/          # P2's workspace
│   └── tls_malware/             # P2's workspace
│
├── backend/                     # P3: Core FastAPI pipeline
│   ├── main.py                  # API endpoints and WebSocket server
│   ├── ingestor.py              # Tails zeek_logs/, extracts features, buffers time-windows
│   ├── orchestrator.py          # Imports the 6 detectors, executes predictions
│   ├── schemas.py               # Pydantic schemas standardizing the final JSON alert
│   ├── requirements.txt
│   └── Dockerfile
│
