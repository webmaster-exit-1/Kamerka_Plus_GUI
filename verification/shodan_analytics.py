"""
shodan_analytics.py – Cost-control and deduplication helpers for Shodan queries.

Count-before-commit workflow
-----------------------------
Before issuing a ``shodan.search()`` call (which costs 1 credit per 100
results), always call :func:`credit_cost_report` first.  It runs the free
``shodan.count()`` and ``shodan.stats()`` methods to produce a report that
lets the analyst decide whether the cost is worthwhile.

Deduplication via last_scanned
-------------------------------
:func:`should_skip_ip` checks the local SQLite ``Device`` table for a recent
scan of the same IP.  If the device was scanned within *max_age_hours*, the
function returns ``True`` and the caller should skip the Shodan look-up.  This
prevents redundant API calls for assets that have not changed.

Usage
-----
    from verification.shodan_analytics import credit_cost_report, should_skip_ip

    report = credit_cost_report(api, "port:502 country:US")
    print(report)

    if not should_skip_ip("1.2.3.4", max_age_hours=24):
        results = api.search("port:502 country:US")
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

#: Default age in hours beyond which a cached scan is considered stale.
DEFAULT_MAX_AGE_HOURS: int = 24

#: Shodan charges 1 query credit per 100 results.  We use this to estimate
#: the credit cost before committing to a full download.
RESULTS_PER_CREDIT: int = 100


def credit_cost_report(
    api: Any,
    query: str,
    facets: Optional[list] = None,
) -> Dict[str, Any]:
    """Build a "Credit Cost vs Result Density" report for *query*.

    Calls the free ``api.count()`` and ``api.stats()`` methods (no credits
    consumed) and returns a structured report that the operator can inspect
    before issuing the actual ``api.search()`` call.

    Parameters
    ----------
    api : shodan.Shodan
        Authenticated Shodan API client.
    query : str
        Shodan search query (e.g. ``"port:502 country:US"``).
    facets : list, optional
        Stat facets to request.  Defaults to
        ``["city:5", "country:5", "org:5"]``.

    Returns
    -------
    dict
        Keys:
        ``query``         : str   – Original query string.
        ``total_results`` : int   – Number of results available.
        ``estimated_credits`` : int – Credits needed for a full download.
        ``facets``        : dict  – Top values for each requested facet.
        ``recommendation``: str  – Human-readable guidance.

    Examples
    --------
    >>> report = credit_cost_report(api, "port:502 country:US")
    >>> print(report["recommendation"])
    'Proceed: 47 results cost 1 credit.'
    """
    if facets is None:
        facets = ["city:5", "country:5", "org:5"]

    report: Dict[str, Any] = {
        "query": query,
        "total_results": 0,
        "estimated_credits": 0,
        "facets": {},
        "recommendation": "",
        "error": None,
    }

    try:
        count_data = api.count(query)
        total = int(count_data.get("total", 0))
        report["total_results"] = total
        report["estimated_credits"] = max(
            1, (total + RESULTS_PER_CREDIT - 1) // RESULTS_PER_CREDIT
        )
    except Exception as exc:
        report["error"] = "count() failed: {}".format(exc)
        logger.warning("Shodan count() failed for '%s': %s", query, exc)
        return report

    try:
        stats_data = api.stats(query, facets=facets)
        report["facets"] = stats_data.get("facets", {})
    except Exception as exc:
        logger.warning("Shodan stats() failed for '%s': %s", query, exc)

    # Build human-readable recommendation
    credits = report["estimated_credits"]
    total = report["total_results"]
    if total == 0:
        report["recommendation"] = (
            "No results found.  Do not proceed – query returns nothing."
        )
    elif credits == 1:
        report["recommendation"] = (
            "Proceed: {} result{} cost 1 credit.".format(
                total, "s" if total != 1 else ""
            )
        )
    else:
        report["recommendation"] = (
            "Caution: {} results will cost {} credits.  "
            "Consider narrowing the query or using a country/city filter.".format(
                total, credits
            )
        )

    return report


def should_skip_ip(ip: str, max_age_hours: int = DEFAULT_MAX_AGE_HOURS) -> bool:
    """Return ``True`` if *ip* was scanned recently enough to skip re-scanning.

    Checks the Django ``Device`` model's ``last_scanned`` field.  If the most
    recent record for this IP has ``last_scanned`` within *max_age_hours*, the
    cached data is considered fresh and there is no need to query Shodan again.

    Parameters
    ----------
    ip : str
        Target IP address.
    max_age_hours : int, optional
        Maximum age in hours before a scan is considered stale (default 24).

    Returns
    -------
    bool
        ``True`` when a recent scan exists (skip); ``False`` when a fresh scan
        is needed (proceed).
    """
    try:
        # Import here to avoid circular imports when this module is used
        # outside the Django context.
        from app_kamerka.models import Device

        cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=max_age_hours)
        exists = Device.objects.filter(
            ip=ip,
            last_scanned__gte=cutoff,
        ).exists()
        if exists:
            logger.debug("Skipping %s – scanned within the last %dh", ip, max_age_hours)
        return exists
    except Exception as exc:
        logger.warning("should_skip_ip DB check failed for %s: %s", ip, exc)
        return False


def update_last_scanned(ip: str) -> None:
    """Stamp ``Device.last_scanned = now()`` for all records with *ip*.

    Called after a successful Shodan API download so subsequent calls to
    :func:`should_skip_ip` will return ``True`` until the cache expires.

    Parameters
    ----------
    ip : str
        Target IP address.
    """
    try:
        from app_kamerka.models import Device

        now = datetime.now(tz=timezone.utc)
        updated = Device.objects.filter(ip=ip).update(last_scanned=now)
        logger.debug("Stamped last_scanned for %s (%d record(s))", ip, updated)
    except Exception as exc:
        logger.warning("update_last_scanned failed for %s: %s", ip, exc)
