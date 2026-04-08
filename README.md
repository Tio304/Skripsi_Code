# Hybrid Network Intrusion Detection System (NIDS)

This workspace contains a real-time hybrid NIDS that combines signature-based
detection and ML anomaly detection in tandem. Signature intelligence can come
from built-in rules, Snort/Suricata rules files, and AlienVault OTX IOC feeds.

## Current Capabilities

1. Policy-based response modes
- detect-only
- block-signature
- soc-queue-ml

2. Rule and threat-intel enrichment
- Snort rules parser/loading
- Suricata rules parser/loading
- Optional Snort Oinkcode rules download
- OTX IOC enrichment (API key and/or local IOC file)

3. Hybrid detection pipeline
- Signature checks and ML scoring run together for each packet/flow
- If a threat is signature-evasive, ML can still flag anomaly behavior

4. Analyst feedback loop for retraining
- Dashboard Ignore/Resolve decisions are written to analyst_feedback.jsonl
- Alerts include model_features snapshots for feedback-based retraining

5. Model lifecycle management
- Per-retrain metrics logged to training_history.json
- Per-run archived model artifacts in models/
- Model registry in model_registry.json
- Rollback tool to restore older model versions

6. Dashboard and launcher
- Flask + REST + HTML dashboard (not Streamlit by default)
- One-command launcher via start_all.ps1

## Main Files

- nids_engine.py: Real-time capture, signature stage, ML stage, policy actions
- flask_app.py: Fast dashboard and REST API
- start_all.ps1: Launch engine + dashboard in separate terminals
- train_xgboost_model.py: Offline training, feedback ingestion, versioning
- compare_training_metrics.py: Retrain metrics comparison report
- rollback_model.py: Roll back active model to previous run

## Quick Start

1. Activate environment

```powershell
& ".\\.venv\\Scripts\\Activate.ps1"
```

2. Run tandem hybrid mode (ML + Snort + Suricata + OTX capable)

```powershell
.\\start_all.ps1 -InterfaceName "Wi-Fi" -ModelPath "model.json" -PolicyMode "detect-only"
```

Optional enrichment arguments:
- -SnortRulesPath "path\\to\\snort.rules"
- -SuricataRulesPath "path\\to\\suricata.rules"
- -OtxApiKey "<your_key>" or -OtxIocFile "path\\to\\otx_iocs.txt"

3. Open dashboard
- http://localhost:5000

## Retraining, Monitoring, and Rollback

1. Retrain with feedback + archive + registry update

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\train_xgboost_model.py --promote-if-better
```

2. Compare metrics across retrains

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\compare_training_metrics.py
```

3. List archived runs

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\rollback_model.py --list
```

4. Roll back to a specific run

```powershell
& ".\\.venv\\Scripts\\python.exe" .\\rollback_model.py --run-id 20260403_153000
```

