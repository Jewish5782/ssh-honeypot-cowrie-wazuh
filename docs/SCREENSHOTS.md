# Screenshots

Images used in the README. All paths are relative to the repo root.

## Included

| File | Description |
|------|-------------|
| `docs/dashboard-overview.png` | Streamlit triage UI — metrics and session list |
| `docs/dashboard-alert-detail.png` | Expanded alert session (reasons, commands, detectors) |
| `docs/dashboard-review.png` | Review queue with promote / dismiss controls |
| `docs/pipeline-cli.png` | CLI pipeline output with scores and reasons |

## How they were produced

```bash
python3 -m venv .venv && source .venv/bin/activate
python3 samples/generate_samples.py

# CLI
python3 src/pipeline.py --logfile samples/cowrie.json -v

# Dashboard
pip install streamlit
streamlit run src/dashboard.py
# open http://localhost:8501
```

## Optional: live Wazuh

A Wazuh dashboard capture is optional. The primary proof for this project is the
Python detection layer (offline CLI + Streamlit). If you run the full Docker
stack and want a SIEM screenshot later, save it as `docs/wazuh-dashboard.png`
and link it from the README.
