import asyncio
from agents.osint_researcher import run as osint_run
from agents.cve_analyst import run as cve_run
from agents.context_enricher import run as enricher_run
from agents.critic import run as critic_run
from agents.synthesis import run as synthesis_run
from agents import data_sources


async def _run_in_executor(fn, *args):
    """Run a synchronous function in a thread pool so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


async def run(query: str) -> dict:
    """
    Orchestrates the full pipeline:
      0. Fetch live data sources in parallel (NVD + ATT&CK + CISA KEV catalog)
      1. Fan out to three worker agents in parallel, passing live data
      2. Pass combined worker output to the critic
      3. Pass critic feedback + worker output to synthesis
      4. Return structured result with all intermediate outputs
    """

    # --- Stage 0: Parallel live data fetch ---
    nvd_data, attack_data, _ = await asyncio.gather(
        _run_in_executor(data_sources.fetch_nvd_data, query),
        _run_in_executor(data_sources.fetch_attack_data, query),
        _run_in_executor(data_sources._fetch_cisa_kev_raw),  # warms the cache
    )

    # Cross-reference NVD CVE IDs against CISA KEV
    cve_ids = [c["id"] for c in nvd_data.get("cves", [])]
    cisa_data = await _run_in_executor(data_sources.fetch_cisa_kev, cve_ids)

    live_sources = {
        "nvd": nvd_data,
        "attack": attack_data,
        "cisa": cisa_data,
    }

    # --- Stage 1: Parallel workers ---
    osint_result, cve_result, enricher_result = await asyncio.gather(
        osint_run(query, attack_data=attack_data),
        cve_run(query, nvd_data=nvd_data, cisa_data=cisa_data),
        enricher_run(query),
    )

    worker_output = {
        "osint": osint_result,
        "cve": cve_result,
        "context": enricher_result,
    }

    # --- Stage 2: Critic review ---
    critic_feedback = await critic_run(query, worker_output)

    # --- Stage 3: Synthesis ---
    final_brief = await synthesis_run(query, worker_output, critic_feedback, live_sources)

    return {
        "query": query,
        "worker_output": worker_output,
        "critic_feedback": critic_feedback,
        "final_brief": final_brief,
        "live_sources": live_sources,
    }
