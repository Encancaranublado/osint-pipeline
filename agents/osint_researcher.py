# OSINT Researcher Agent
# Gathers open-source intelligence on a threat actor or CVE.

import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are an OSINT analyst specializing in cyber threat intelligence.
Your job is to gather and summarize open-source intelligence on a given threat actor or CVE.

Focus on:
- Known aliases, origin, and attribution
- Targeted sectors and geographies
- Known TTPs (Tactics, Techniques, and Procedures)
- Notable campaigns or incidents
- Public reporting sources (threat intel blogs, government advisories, etc.)

If the query is a CVE ID, focus on public disclosure details, proof-of-concept availability,
and known exploitation in the wild. Be specific and factual. Do not speculate beyond what is
publicly known.

When live ATT&CK data is provided, treat those technique IDs and names as ground truth.
Build your TTP analysis around them rather than relying solely on training knowledge."""


def _format_attack_context(attack_data: dict) -> str:
    if not attack_data.get("available"):
        return f"[MITRE ATT&CK data unavailable: {attack_data.get('error', 'unknown error')}]"

    if not attack_data.get("group_found"):
        return "[No matching threat group found in MITRE ATT&CK STIX data.]"

    aliases = ", ".join(attack_data.get("aliases", [])) or "none listed"
    techniques = attack_data.get("techniques", [])
    technique_lines = "\n".join(
        f"  - {t['technique_id']} – {t['name']}" for t in techniques
    )

    return (
        f"Source: {attack_data['source']}\n"
        f"Group: {attack_data['group_name']} (aliases: {aliases})\n"
        f"Techniques ({len(techniques)} total):\n{technique_lines}"
    )


async def run(query: str, attack_data: dict = None) -> str:
    live_context = ""
    if attack_data is not None:
        live_context = (
            "\n\nLIVE MITRE ATT&CK DATA [HIGH CONFIDENCE — use as ground truth]:\n"
            + _format_attack_context(attack_data)
        )

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Provide an OSINT summary for: {query}{live_context}",
            }
        ],
    )
    return message.content[0].text
