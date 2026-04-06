# Data Sources
# Fetches live data from NVD, MITRE ATT&CK STIX, and CISA KEV.
# All functions return a dict with an "available" boolean so callers can
# fall back gracefully if a source is unreachable.

import re
import requests
from functools import lru_cache

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

TIMEOUT = 15
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def fetch_nvd_data(query: str) -> dict:
    """
    Fetch CVE data from NVD.
    - CVE ID query: direct lookup for that CVE.
    - Threat actor query: keyword search, top 10 results by CVSS score.
    """
    try:
        if CVE_PATTERN.match(query.strip()):
            params = {"cveId": query.strip().upper()}
        else:
            params = {"keywordSearch": query, "resultsPerPage": 10}

        resp = requests.get(NVD_URL, params=params, timeout=TIMEOUT)
        resp.raise_for_status()
        raw = resp.json().get("vulnerabilities", [])

        cves = []
        for item in raw:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            description = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available.",
            )

            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else None
            severity = cvss_v3[0]["cvssData"]["baseSeverity"] if cvss_v3 else None
            vector = cvss_v3[0]["cvssData"].get("vectorString") if cvss_v3 else None

            cves.append({
                "id": cve_id,
                "description": description[:300],
                "cvss_score": score,
                "severity": severity,
                "vector": vector,
                "published": cve.get("published", "")[:10],
            })

        # Sort by CVSS score descending so most critical appear first
        cves.sort(key=lambda c: c["cvss_score"] or 0, reverse=True)

        return {"available": True, "source": "NVD API", "cves": cves}

    except Exception as e:
        return {"available": False, "error": str(e), "source": "NVD API", "cves": []}


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _fetch_attack_bundle() -> list:
    """Download and cache the full MITRE ATT&CK STIX bundle (~20 MB)."""
    resp = requests.get(ATTACK_URL, timeout=60)
    resp.raise_for_status()
    return resp.json().get("objects", [])


def fetch_attack_data(query: str) -> dict:
    """
    Search the MITRE ATT&CK STIX bundle for techniques associated with a
    threat actor. Returns an empty technique list (not an error) if the
    actor is not found — e.g. for CVE-only queries.
    """
    try:
        objects = _fetch_attack_bundle()

        # Map attack-pattern STIX IDs → technique metadata
        techniques_by_stix_id = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                ext_refs = obj.get("external_references", [])
                tid = next(
                    (r["external_id"] for r in ext_refs if r.get("source_name") == "mitre-attack"),
                    None,
                )
                if tid:
                    techniques_by_stix_id[obj["id"]] = {
                        "technique_id": tid,
                        "name": obj.get("name", ""),
                    }

        # Find the intrusion-set matching the query
        query_lower = query.lower()
        group = None
        for obj in objects:
            if obj.get("type") != "intrusion-set":
                continue
            name_match = query_lower in obj.get("name", "").lower()
            alias_match = any(
                query_lower in alias.lower() for alias in obj.get("aliases", [])
            )
            if name_match or alias_match:
                group = obj
                break

        if not group:
            return {
                "available": True,
                "source": "MITRE ATT&CK STIX",
                "group_found": False,
                "techniques": [],
            }

        # Collect techniques via "uses" relationships
        group_stix_id = group["id"]
        used_technique_ids = {
            obj["target_ref"]
            for obj in objects
            if (
                obj.get("type") == "relationship"
                and obj.get("relationship_type") == "uses"
                and obj.get("source_ref") == group_stix_id
                and obj.get("target_ref", "").startswith("attack-pattern--")
            )
        }

        techniques = sorted(
            [
                techniques_by_stix_id[stix_id]
                for stix_id in used_technique_ids
                if stix_id in techniques_by_stix_id
            ],
            key=lambda t: t["technique_id"],
        )

        return {
            "available": True,
            "source": "MITRE ATT&CK STIX",
            "group_found": True,
            "group_name": group.get("name"),
            "aliases": group.get("aliases", []),
            "techniques": techniques[:40],  # cap at 40 to avoid context bloat
        }

    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "source": "MITRE ATT&CK STIX",
            "techniques": [],
        }


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _fetch_cisa_kev_raw() -> list:
    """Download and cache the full CISA KEV catalog."""
    resp = requests.get(CISA_KEV_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def fetch_cisa_kev(cve_ids: list) -> dict:
    """
    Cross-reference a list of CVE IDs against the CISA KEV catalog.
    Returns only the entries that match.
    """
    try:
        catalog = _fetch_cisa_kev_raw()
        target_ids = {cve_id.upper() for cve_id in cve_ids}

        matches = [
            {
                "cve_id": entry["cveID"],
                "vendor": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "date_added": entry.get("dateAdded", ""),
                "due_date": entry.get("dueDate", ""),
                "required_action": entry.get("requiredAction", ""),
            }
            for entry in catalog
            if entry.get("cveID", "").upper() in target_ids
        ]

        return {
            "available": True,
            "source": "CISA KEV",
            "matched_count": len(matches),
            "matches": matches,
        }

    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "source": "CISA KEV",
            "matches": [],
        }
