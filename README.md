# OSINT Threat Intelligence Pipeline

A multi-agent threat intelligence summarization pipeline built with Python and Streamlit. Enter a threat actor name or CVE ID and get a MITRE ATT&CK-aligned intelligence brief sourced from live APIs.

## Live Data Sources

- **NVD API** — real CVE data, CVSS scores, and affected systems
- **MITRE ATT&CK STIX** — live TTP mapping for known threat groups
- **CISA KEV Catalog** — cross-references CVEs against actively exploited vulnerabilities

## Architecture

Multi-agent pipeline powered by the Anthropic API (`claude-sonnet-4-6`):

```
app.py                  # Streamlit UI
agents/
  orchestrator.py       # Fans out to workers, sequences critic → synthesis
  osint_researcher.py   # Open-source intel + ATT&CK technique mapping
  cve_analyst.py        # CVE details, CVSS scores, CISA KEV cross-reference
  context_enricher.py   # Geopolitical and campaign context
  critic.py             # Reviews combined output for gaps and quality
  synthesis.py          # Produces final MITRE ATT&CK-aligned brief
  data_sources.py       # Live API integrations (NVD, ATT&CK, CISA KEV)
```

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
# Add your ANTHROPIC_API_KEY to .env
streamlit run app.py
```

## Deployment

Deployable on [Streamlit Cloud](https://streamlit.io/cloud). Set `ANTHROPIC_API_KEY` as a secret in the app settings.
