# Synthesis Agent
# Produces a final MITRE ATT&CK-aligned intelligence brief.

import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a senior threat intelligence analyst producing a finished
intelligence brief for a security operations team.

You will receive:
1. Combined output from three intelligence workers (OSINT, CVE analysis, geopolitical context)
2. A critic's review identifying gaps and weaknesses in that output
3. A summary of which live data sources were successfully queried

Your job is to synthesize all of this into a single, polished, MITRE ATT&CK-aligned
intelligence brief. Address the critic's feedback where possible — if a gap cannot be
filled from the available information, acknowledge it explicitly in the brief.

Apply confidence levels to each section using these rules:
- **[HIGH]** — finding is directly sourced from live API data (NVD, ATT&CK STIX, CISA KEV)
- **[MEDIUM]** — finding is corroborated by multiple aspects of the worker output
- **[LOW]** — finding comes from a single source or is inferred

Structure your brief exactly as follows:

## Threat Overview
A 2-3 sentence executive summary of the threat actor or CVE.

## Attribution & Motivation
Suspected origin, sponsorship, and strategic motivation. Tag each claim with a confidence level.

## MITRE ATT&CK Techniques
A structured list of relevant techniques. For techniques sourced from live ATT&CK STIX data,
mark them [HIGH]. Format each as:
- **TXXXX – Technique Name** [CONFIDENCE]: one-sentence description of how this actor/CVE uses it.

## Targeted Sectors & Geographies
Who is at risk and where. Tag each claim with a confidence level.

## Key Vulnerabilities & Indicators
Notable CVEs, known IOCs, or weaponized tools. CVEs sourced from live NVD data are [HIGH].
CVEs that appear in the CISA KEV catalog should be marked **[ACTIVELY EXPLOITED]**.

## Analyst Assessment
2-3 sentences on the current threat level, likely near-term activity, and recommended
defensive priority.

## Intelligence Gaps
Bullet list of what remains unknown or unconfirmed.

## Data Sources
List each source queried, its status (live / unavailable), and what it contributed.

Write in clear, professional prose. Avoid hedging language unless genuinely uncertain.
This brief will be read by a SOC team making defensive decisions."""


def _format_source_status(live_sources: dict) -> str:
    if not live_sources:
        return "[No live source metadata available.]"

    lines = []
    for key, data in live_sources.items():
        source_name = data.get("source", key.upper())
        if data.get("available"):
            if key == "attack" and data.get("group_found"):
                detail = f"{len(data.get('techniques', []))} techniques found for {data.get('group_name')}"
            elif key == "nvd":
                detail = f"{len(data.get('cves', []))} CVE(s) returned"
            elif key == "cisa":
                detail = f"{data.get('matched_count', 0)} KEV match(es)"
            else:
                detail = "available"
            lines.append(f"  - {source_name}: LIVE — {detail}")
        else:
            lines.append(f"  - {source_name}: UNAVAILABLE — {data.get('error', 'unknown error')}")

    return "\n".join(lines)


async def run(
    query: str,
    worker_output: dict,
    critic_feedback: str,
    live_sources: dict = None,
) -> str:
    source_status = _format_source_status(live_sources or {})

    combined = f"""OSINT RESEARCH:
{worker_output['osint']}

CVE/VULNERABILITY ANALYSIS:
{worker_output['cve']}

GEOPOLITICAL & CAMPAIGN CONTEXT:
{worker_output['context']}

CRITIC FEEDBACK:
{critic_feedback}

LIVE DATA SOURCE STATUS:
{source_status}"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Original query: {query}\n\n"
                    f"Produce a final intelligence brief using the following:\n\n{combined}"
                ),
            }
        ],
    )
    return message.content[0].text
