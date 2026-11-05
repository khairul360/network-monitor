# Home DNS Monitor

A lightweight **network security monitor** that watches DNS traffic on a network and raises alerts for suspicious activity, with a live dashboard. Built as a hands-on defensive-security / network-monitoring project.

## What it does
`monitor.py` sniffs DNS queries and flags behaviour commonly linked to malware and data exfiltration:

| Rule | What it catches | MITRE ATT&CK | Severity |
|------|-----------------|--------------|----------|
| **DGA** | High-entropy domains (algorithmically generated) | T1568.002 | medium |
| **TXT** | TXT-record queries (possible DNS tunneling) | T1071.004 | low |
| **LONG** | Unusually long domains (possible tunneling) | T1071.004 | medium |
| **RATE** | Spikes in query rate | T1071.004 | high |

Common cloud/CDN domains are allow-listed to cut down on noise, and each alert type has a cooldown so it doesn't repeat. Queries and alerts are stored in a local SQLite database.

`dashboard.py` is a **Streamlit** dashboard showing total queries, alert counts, high-severity totals, alerts by rule, and a filterable alert table with live auto-refresh.

## Tech
`Python` · `Scapy` (packet capture) · `SQLite` · `Streamlit` · `pandas`

## Running it
```bash
pip install scapy streamlit pandas

# 1. Capture and analyse DNS traffic (needs admin/root for sniffing)
sudo python monitor.py

# 2. In another terminal, launch the dashboard
streamlit run dashboard.py
```

## Notes
Intended for monitoring **your own network** for learning and defensive purposes. The alert rules are heuristics, so expect to tune the allow-list and thresholds for your environment.
