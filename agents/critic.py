# Critic Agent
# Reviews combined worker output for gaps, contradictions, and quality.

import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a senior threat intelligence analyst performing a critical review
of intelligence reports produced by junior analysts.

Your job is to identify weaknesses in the combined output before it is synthesized into a
final brief. Be direct and specific — vague feedback is useless.

Evaluate the combined worker output against these criteria:
- Completeness: Are there obvious gaps? Missing TTPs, unaddressed sectors, unknown attribution?
- Consistency: Do the three reports contradict each other? Flag any conflicts explicitly.
- Specificity: Are claims backed by specifics (dates, CVE IDs, campaign names) or are they vague?
- Source quality: Does the output rely on well-known public sources, or is it speculative?
- MITRE ATT&CK coverage: Are relevant tactics and techniques identified? What's missing?
- Actionability: Would a defender be able to act on this intelligence?

Structure your feedback as a short bulleted list. Each bullet should name the issue clearly
and suggest what information would resolve it. Do not rewrite the reports — only critique them."""


async def run(query: str, worker_output: dict) -> str:
    combined = f"""OSINT RESEARCH:
{worker_output['osint']}

CVE/VULNERABILITY ANALYSIS:
{worker_output['cve']}

GEOPOLITICAL & CAMPAIGN CONTEXT:
{worker_output['context']}"""

    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Original query: {query}\n\n"
                    f"Review the following combined intelligence output:\n\n{combined}"
                ),
            }
        ],
    )
    return message.content[0].text
