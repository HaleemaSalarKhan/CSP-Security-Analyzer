"""Synchronous CSP collection with requests only."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable, List

import pandas as pd
import requests


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0 Safari/537.36 CSP-Security-Analyzer/1.0"
)


def fetch_csp_for_domain(domain: str, timeout: int = 12, retries: int = 1) -> dict:
    """Fetch CSP headers for one domain using requests with one retry."""
    clean_domain = str(domain).strip().lower()
    url = f"https://{clean_domain}"
    headers = {"User-Agent": USER_AGENT}

    last_error = ""
    for attempt in range(retries + 1):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True,
            )
            csp_header = response.headers.get("Content-Security-Policy", "")
            report_only = response.headers.get("Content-Security-Policy-Report-Only", "")
            return {
                "domain": clean_domain,
                "csp_header": csp_header,
                "report_only_header": report_only,
                "status_code": response.status_code,
                "has_csp": int(bool(csp_header)),
            }
        except requests.RequestException as exc:
            last_error = str(exc)
            if attempt < retries:
                time.sleep(1)

    return {
        "domain": clean_domain,
        "csp_header": "",
        "report_only_header": "",
        "status_code": None,
        "has_csp": 0,
        "error": last_error,
    }


def collect_csp_dataset(
    domains: Iterable[str],
    delay_seconds: float = 0.7,
    timeout: int = 12,
    retries: int = 1,
    skip_unreachable: bool = True,
) -> pd.DataFrame:
    """Collect CSP data for many domains with a polite delay."""
    rows: List[dict] = []

    for index, domain in enumerate(domains, start=1):
        print(f"[{index}] Fetching https://{domain}")
        row = fetch_csp_for_domain(domain, timeout=timeout, retries=retries)
        if not skip_unreachable or row.get("status_code") is not None:
            rows.append(row)
        time.sleep(delay_seconds)

    expected_columns = [
        "domain",
        "csp_header",
        "report_only_header",
        "status_code",
        "has_csp",
        "error",
    ]
    return pd.DataFrame(rows).reindex(columns=expected_columns)


def load_tranco_domains(path: str | Path, limit: int = 1000) -> List[str]:
    """Load domains from a Tranco CSV file.

    Tranco CSV files commonly contain either:
    - rank,domain with no header
    - a domain column
    """
    csv_path = Path(path)
    raw = pd.read_csv(csv_path, header=None)

    if raw.shape[1] >= 2:
        domains = raw.iloc[:, 1].astype(str)
    else:
        domains = raw.iloc[:, 0].astype(str)

    domains = domains.str.strip().str.lower()
    domains = domains[domains.str.contains(".", regex=False)]
    return domains.drop_duplicates().head(limit).tolist()
