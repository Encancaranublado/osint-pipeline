# Streamlit frontend
# Takes a threat actor or CVE as input and displays the final intelligence brief.

import asyncio
from concurrent.futures import ThreadPoolExecutor
import streamlit as st
from agents.orchestrator import run as orchestrate

st.set_page_config(
    page_title="OSINT Threat Intelligence Pipeline",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ OSINT Threat Intelligence Pipeline")
st.caption("Enter a threat actor name (e.g. APT29, Lazarus Group) or a CVE ID (e.g. CVE-2024-1234)")

query = st.text_input(
    label="Threat Actor or CVE",
    placeholder="e.g. APT29 or CVE-2021-44228",
)

run_button = st.button("Generate Intelligence Brief", type="primary", disabled=not query)

if run_button and query:
    with st.spinner("Running pipeline — this may take 30–60 seconds..."):
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, orchestrate(query))
            result = future.result()

    st.success("Pipeline complete.")

    # --- Live data source status ---
    st.markdown("---")
    st.subheader("Live Data Sources")
    cols = st.columns(3)
    source_labels = {
        "nvd": "NVD API",
        "attack": "MITRE ATT&CK STIX",
        "cisa": "CISA KEV",
    }
    for col, (key, label) in zip(cols, source_labels.items()):
        data = result["live_sources"].get(key, {})
        if data.get("available"):
            col.success(f"**{label}** — live")
        else:
            col.error(f"**{label}** — unavailable")

    # --- Final Brief ---
    st.markdown("---")
    st.subheader("Final Intelligence Brief")
    st.markdown(result["final_brief"])

    # --- Intermediate outputs (collapsible) ---
    st.markdown("---")
    with st.expander("OSINT Research"):
        st.markdown(result["worker_output"]["osint"])

    with st.expander("CVE / Vulnerability Analysis"):
        st.markdown(result["worker_output"]["cve"])

    with st.expander("Geopolitical & Campaign Context"):
        st.markdown(result["worker_output"]["context"])

    with st.expander("Critic Feedback"):
        st.markdown(result["critic_feedback"])
