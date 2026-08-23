"""
Personalised Vulnerability Triage — core engine.

Design principle (per brief): rules must be VISIBLE. No black-box scoring.
Every included/excluded item carries a reason. Nothing is invented.

Pipeline: LOAD -> MATCH -> RANK -> EXPLAIN -> PRESENT (top 5)
"""

import csv
import json
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Alias table — extend this as you discover mismatches in the real data pack.
# Keys and values must be lowercase, normalised vendor/product strings.
# ---------------------------------------------------------------------------
ALIASES = {
    ("apache", "httpd"): ("apache", "http_server"),
    ("mysql", "mysql"): ("oracle", "mysql"),
    ("postgres", "postgres"): ("postgresql", "postgresql"),
    ("ssh", "openssh"): ("openbsd", "openssh"),
}


def normalise(vendor: str, product: str):
    v, p = vendor.strip().lower(), product.strip().lower()
    return ALIASES.get((v, p), (v, p))


@dataclass
class VulnRow:
    cve_id: str
    published_date: str
    description: str
    cvss_score: Optional[float]
    vendor: str
    product: str
    version_start: Optional[str]
    version_end: Optional[str]
    version_note: str
    in_kev: bool
    epss_score: Optional[float]
    reference_url: str
    source_snapshot_date: str


@dataclass
class MatchResult:
    row: VulnRow
    outcome: str  # "include", "include_verify", "exclude"
    reason: str
    matched_tech: Optional[dict] = None
    score: float = 0.0
    factors: list = field(default_factory=list)
    confidence: str = "medium"


def load_vulnerabilities(path: str) -> list[VulnRow]:
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(VulnRow(
                cve_id=r["cve_id"],
                published_date=r["published_date"],
                description=r["description"],
                cvss_score=float(r["cvss_score"]) if r.get("cvss_score") else None,
                vendor=r["vendor"].strip().lower(),
                product=r["product"].strip().lower(),
                version_start=r.get("version_start") or None,
                version_end=r.get("version_end") or None,
                version_note=r.get("version_note", ""),
                in_kev=str(r.get("in_kev", "")).strip().lower() == "true",
                epss_score=float(r["epss_score"]) if r.get("epss_score") else None,
                reference_url=r.get("reference_url", ""),
                source_snapshot_date=r.get("source_snapshot_date", ""),
            ))
    return rows


def load_profiles(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["profiles"]


def _version_tuple(v: str):
    """Parse a clean numeric dotted version into a comparable tuple. Returns
    None if it isn't clean numeric — caller must treat that as unverifiable."""
    try:
        return tuple(int(p) for p in v.strip().split("."))
    except (ValueError, AttributeError):
        return None


def _in_range(installed: str, start: Optional[str], end: Optional[str]) -> Optional[bool]:
    """True/False if we can safely compare, None if unverifiable."""
    iv = _version_tuple(installed)
    if iv is None:
        return None
    if start:
        sv = _version_tuple(start)
        if sv is None:
            return None
        if iv < sv:
            return False
    if end:
        ev = _version_tuple(end)
        if ev is None:
            return None
        if iv > ev:
            return False
    return True


def match_profile(profile: dict, vulns: list[VulnRow]) -> list[MatchResult]:
    results = []
    tech_lookup = {}
    for t in profile["technologies"]:
        nv, np_ = normalise(t["vendor"], t["product"])
        tech_lookup[(nv, np_)] = t

    for row in vulns:
        key = (row.vendor, row.product)
        tech = tech_lookup.get(key)

        if tech is None:
            results.append(MatchResult(
                row=row, outcome="exclude",
                reason=f"{profile['name']} does not use {row.vendor}/{row.product}."
            ))
            continue

        # version-unsafe: no start/end recorded at all but a note flags it
        if row.version_note:
            results.append(MatchResult(
                row=row, outcome="include_verify",
                reason=f"Version comparison unreliable ({row.version_note}). "
                       f"Installed version {tech['version']} could not be safely checked.",
                matched_tech=tech, confidence="low",
            ))
            continue

        if not row.version_start and not row.version_end:
            # unbounded range = every version affected
            results.append(MatchResult(
                row=row, outcome="include",
                reason="Affects all versions of this product (no bound recorded).",
                matched_tech=tech,
            ))
            continue

        verdict = _in_range(tech["version"], row.version_start, row.version_end)
        if verdict is None:
            results.append(MatchResult(
                row=row, outcome="include_verify",
                reason=f"Installed version {tech['version']} format could not be "
                       f"safely compared against range {row.version_start}-{row.version_end}.",
                matched_tech=tech, confidence="low",
            ))
        elif verdict is True:
            results.append(MatchResult(
                row=row, outcome="include",
                reason=f"Installed version {tech['version']} falls within affected "
                       f"range {row.version_start}-{row.version_end}.",
                matched_tech=tech,
            ))
        else:
            results.append(MatchResult(
                row=row, outcome="exclude",
                reason=f"Installed version {tech['version']} is outside affected "
                       f"range {row.version_start}-{row.version_end}.",
                matched_tech=tech,
            ))

    return results


# ---------------------------------------------------------------------------
# Scoring — transparent, additive, every contribution visible.
# Tune the weights, but keep them visible in the output (brief requires this).
# ---------------------------------------------------------------------------
WEIGHTS = {
    "kev": 40,
    "exposure_internet": 20,
    "exposure_internal": 5,
    "importance_critical": 15,
    "importance_high": 10,
    "importance_normal": 3,
    "epss_multiplier": 20,   # epss_score (0-1) * this
    "cvss_multiplier": 1.0,  # cvss_score (0-10) * this
}


def score_result(mr: MatchResult, profile: dict) -> MatchResult:
    if mr.outcome == "exclude":
        mr.score = -1
        return mr

    row = mr.row
    factors = []
    total = 0.0

    if row.in_kev:
        total += WEIGHTS["kev"]
        factors.append(("Confirmed exploitation (CISA KEV)", WEIGHTS["kev"]))

    if profile["exposure"] == "internet-facing":
        total += WEIGHTS["exposure_internet"]
        factors.append(("Internet-facing exposure", WEIGHTS["exposure_internet"]))
    else:
        total += WEIGHTS["exposure_internal"]
        factors.append(("Internal-only exposure", WEIGHTS["exposure_internal"]))

    imp_key = f"importance_{profile['importance']}"
    imp_val = WEIGHTS.get(imp_key, 0)
    total += imp_val
    factors.append((f"Service importance: {profile['importance']}", imp_val))

    if row.epss_score is not None:
        contrib = round(row.epss_score * WEIGHTS["epss_multiplier"], 1)
        total += contrib
        factors.append((f"EPSS exploitation probability ({row.epss_score:.0%})", contrib))

    if row.cvss_score is not None:
        contrib = round(row.cvss_score * WEIGHTS["cvss_multiplier"], 1)
        total += contrib
        factors.append((f"CVSS technical severity ({row.cvss_score})", contrib))

    if mr.outcome == "include_verify":
        total *= 0.6  # discount for unverified match — reflected in confidence too
        factors.append(("Unverified version match — confidence discount applied", "x0.6"))

    mr.score = round(total, 1)
    mr.factors = factors
    if mr.outcome == "include_verify":
        mr.confidence = "low"
    elif row.version_note or row.epss_score is None:
        mr.confidence = "medium"
    else:
        mr.confidence = "high"
    return mr


def priority_label(score: float) -> str:
    if score >= 70:
        return "URGENT"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def next_step(mr: MatchResult) -> str:
    if mr.outcome == "include_verify":
        return "Verify the installed version against the reference link before acting."
    if mr.row.in_kev:
        return "Patch immediately — this is under confirmed active exploitation."
    if mr.score >= 45:
        return "Patch or apply vendor mitigation this week; review vendor guidance."
    if mr.score >= 20:
        return "Schedule a patch in the next maintenance window; monitor for updates."
    return "Monitor — no immediate action required, but keep on the watch list."


def top_five(profile: dict, vulns: list[VulnRow]) -> tuple[list[MatchResult], list[MatchResult]]:
    """Returns (top5_included, all_excluded) — excluded list is kept so the
    negative test can be demonstrated."""
    matches = match_profile(profile, vulns)
    scored = [score_result(m, profile) for m in matches]

    included = [m for m in scored if m.outcome in ("include", "include_verify")]
    excluded = [m for m in scored if m.outcome == "exclude"]

    included.sort(key=lambda m: m.score, reverse=True)
    return included[:5], excluded


def render_result_card(mr: MatchResult) -> str:
    row = mr.row
    factor_lines = "\n".join(f"      + {name}: {val}" for name, val in mr.factors)
    verify_flag = " [NEEDS VERIFICATION]" if mr.outcome == "include_verify" else ""
    return f"""
[{priority_label(mr.score)}] {row.cve_id}{verify_flag}  (score {mr.score})
  What: {row.description}
  Matched: {row.vendor}/{row.product} — your service: {mr.matched_tech['version'] if mr.matched_tech else 'n/a'}
  Why it matters:
{factor_lines}
  Next step: {next_step(mr)}
  Confidence: {mr.confidence} — {mr.reason}
  Source: {row.reference_url} (NVD, snapshot {row.source_snapshot_date})
""".strip()


def find_negative_test_example(excluded: list[MatchResult]) -> Optional[MatchResult]:
    """Required by brief: show one high-CVSS (>=9.0) item that was excluded, and why."""
    candidates = [m for m in excluded if (m.row.cvss_score or 0) >= 9.0]
    if not candidates:
        return None
    return max(candidates, key=lambda m: m.row.cvss_score)


if __name__ == "__main__":
    vulns = load_vulnerabilities("data/vulnerabilities.csv")
    profiles = load_profiles("data/profiles.json")

    for profile in profiles:
        print("=" * 70)
        print(f"TOP 5 FOR: {profile['name']}  ({profile['exposure']}, {profile['importance']}, service: {profile['service']})")
        print("=" * 70)
        top5, excluded = top_five(profile, vulns)
        for mr in top5:
            print(render_result_card(mr))
            print()

        neg = find_negative_test_example(excluded)
        if neg:
            print(f"-- NEGATIVE TEST: {neg.row.cve_id} has CVSS {neg.row.cvss_score} "
                  f"but was excluded. Reason: {neg.reason}")
        print()
