# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

OSINT Threat Intelligence Summarization Pipeline — a multi-agent demo app built with Python and Streamlit. Takes a threat actor name or CVE ID as input and produces a MITRE ATT&CK-aligned intelligence brief.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Streamlit app
streamlit run app.py

# Copy and populate env
cp .env.example .env
```

## Architecture

All agents use the Anthropic API directly (`claude-sonnet-4-6`). No FastAPI — local only.

```
app.py                  # Streamlit UI — input + output display
agents/
  orchestrator.py       # Entry point: fans out to workers in parallel, then sequences critic → synthesis
  osint_researcher.py   # Worker: open-source intel on threat actor or CVE
  cve_analyst.py        # Worker: CVE details, CVSS scores, affected systems
  context_enricher.py   # Worker: geopolitical, sector, and campaign context
  critic.py             # Reviews combined worker output for gaps and quality
  synthesis.py          # Produces final MITRE ATT&CK-aligned brief
```

**Data flow:** `app.py` calls `orchestrator.run(query)` → orchestrator fans out to the three worker agents concurrently (via `asyncio`) → worker results are passed to the critic → critic feedback + worker results are passed to synthesis → final brief returned to `app.py` for display.

## Key conventions

- Each agent exposes a single async function: `async def run(query: str, ...) -> str`
- The orchestrator passes the raw query to all three workers, then assembles their outputs before calling critic and synthesis
- Use `python-dotenv` to load `ANTHROPIC_API_KEY` from `.env`
- Model: `claude-sonnet-4-6` throughout
