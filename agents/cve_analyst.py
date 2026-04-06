# CVE/NVD Analyst Agent
# Analyzes CVE details, CVSS scores, and affected systems.

import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a vulnerability analyst specializing in CVE and NVD data interpretation.
Your job is to analyze and summarize vulnerability details for a given CVE ID or threat actor.

Focus on:
- CVE ID, description, and publication date
- CVSS v3 base score, vector string, and severity rating
- Affected vendors, products, and versions
- Vulnerability type (e.g. RCE, LPE, SQLi, buffer overflow)
- Patch availability and remediation guidance
- Known exploitation status (in the wild, ransomware use, APT use)

If the query is a threat actor rather than a CVE, summarize the CVEs most commonly associated
with that actor — focusing on the highest-severity and most actively exploited ones.

When live NVD data is provided, treat those CVE IDs, scores, and descriptions as ground truth.
When CISA KEV matches are provided, explicitly flag those CVEs as actively exploited and
highlight their required remediation actions.

Be precise with version numbers, scores, and dates. If a detail is unknown, say so explicitly
rather than guessing."""


def _format_nvd_context(nvd_data: dict) -> str:
    if not nvd_data.get("available"):
        return f"[NVD data unavailable: {nvd_data.get('error', 'unknown error')}]"

    cves = nvd_data.get("cves", [])
    if not cves:
        return "[No CVEs returned from NVD for this query.]"

    lines = []
    for c in cves:
        score_str = f"CVSS {c['cvss_score']} ({c['severity']})" if c["cvss_score"] else "No CVSS score"
        lines.append(
            f"  - {c['id']} [{score_str}] Published: {c['published']}\n"
            f"    {c['description']}"
        )

    return f"Source: {nvd_data['source']}\n" + "\n".join(lines)


def _format_cisa_context(cisa_data: dict) -> str:
    if not cisa_data.get("available"):
        return f"[CISA KEV data unavailable: {cisa_data.get('error', 'unknown error')}]"

    matches = cisa_data.get("matches", [])
    if not matches:
        return "[No CVEs from this query appear in the CISA KEV catalog.]"

    lines = []
    for m in matches:
        lines.append(
            f"  - {m['cve_id']}: {m['vulnerability_name']} ({m['vendor']} {m['product']})\n"
            f"    Added: {m['date_added']} | Due: {m['due_date']}\n"
            f"    Required action: {m['required_action']}"
        )

    return (
        f"Source: {cisa_data['source']} — {cisa_data['matched_count']} match(es):\n"
        + "\n".join(lines)
    )


async def run(query: str, nvd_data: dict = None, cisa_data: dict = None) -> str:
    live_context = ""

    if nvd_data is not None:
        live_context += (
            "\n\nLIVE NVD DATA [HIGH CONFIDENCE — use as ground truth]:\n"
            + _format_nvd_context(nvd_data)
        )

    if cisa_data is not None:
        live_context += (
            "\n\nLIVE CISA KEV CROSS-REFERENCE [HIGH CONFIDENCE — actively exploited]:\n"
            + _format_cisa_context(cisa_data)
        )

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Provide a CVE/vulnerability analysis for: {query}{live_context}",
            }
        ],
    )
    return message.content[0].text
