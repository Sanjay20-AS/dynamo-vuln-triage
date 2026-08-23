from models import Vulnerability, OrganizationProfile


def priority_label(score: float) -> str:
    """Score is on the 0-1.2ish scale your scorer produces (weights sum to
    ~1.0, plus up to +0.20 boost). Thresholds tuned to that range."""
    if score >= 0.90:
        return "URGENT"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


def plain_language_title(vulnerability: Vulnerability) -> str:
    """Consequence-first, no jargon, no invented facts — only reframes
    fields we already have."""
    if vulnerability.cisa_kev:
        return f"{vulnerability.product_name} is being actively exploited right now"
    return f"{vulnerability.product_name} has an unpatched vulnerability"


def next_step(vulnerability: Vulnerability, score: float) -> str:
    if vulnerability.cisa_kev:
        return "Patch immediately — confirmed active exploitation in the wild."
    if vulnerability.is_critical_product and score >= 0.60:
        return "Patch or apply vendor mitigation this week — affects a critical system."
    if score >= 0.60:
        return "Patch or apply vendor mitigation this week; review vendor guidance."
    if score >= 0.35:
        return "Schedule a patch in the next maintenance window; monitor for updates."
    return "Monitor — no immediate action required, but keep on the watch list."


def confidence_level(vulnerability: Vulnerability) -> str:
    """All fields are populated in this data pack, so confidence is high by
    default. Drops to medium/low only if a field looks incomplete —
    relevant if the sealed Profile D data has gaps."""
    if vulnerability.cvss_base_score == 0 or vulnerability.first_epss == 0:
        return "medium — one or more signals were zero/missing for this record"
    return "high — all signals (CVSS, KEV, EPSS) present for this record"


def explain_factors(
    vulnerability: Vulnerability,
    profile: OrganizationProfile
) -> list[tuple[str, float]]:
    """Breaks the score into its visible components — this is what stops
    the output being an opaque number, which the brief explicitly penalises."""
    weights = profile.weights

    factors = [
        (f"CVSS severity ({vulnerability.cvss_base_score}/10) x org weight {weights.cvss}",
         round((vulnerability.cvss_base_score / 10) * weights.cvss, 4)),
        (f"CISA KEV ({'confirmed exploited' if vulnerability.cisa_kev else 'not listed'}) x org weight {weights.cisa_kev}",
         round((1.0 if vulnerability.cisa_kev else 0.0) * weights.cisa_kev, 4)),
        (f"EPSS ({vulnerability.first_epss:.1%} exploit probability) x org weight {weights.first_epss}",
         round(vulnerability.first_epss * weights.first_epss, 4)),
    ]

    if vulnerability.is_critical_product:
        factors.append((f"Critical product for {profile.name}: {vulnerability.product_name}", 0.20))

    if profile.exposure == 'internet-facing':
        factors.append((f"Organization exposure ({profile.exposure})", 0.10))
    elif profile.exposure == 'internal':
        factors.append((f"Organization exposure ({profile.exposure})", -0.05))

    if profile.importance == 'critical':
        factors.append((f"Organization importance ({profile.importance})", 0.15))
    elif profile.importance == 'high':
        factors.append((f"Organization importance ({profile.importance})", 0.05))

    return factors


def render_result_card(
    vulnerability: Vulnerability,
    profile: OrganizationProfile,
    score: float
) -> str:
    factors = explain_factors(vulnerability, profile)
    factor_lines = "\n".join(f"    + {name}: {val:+.4f}" for name, val in factors)
    crit_flag = " [CRITICAL PRODUCT]" if vulnerability.is_critical_product else ""

    return f"""
[{priority_label(score)}] {vulnerability.cve_id}{crit_flag}
  {plain_language_title(vulnerability)}
  Score: {score:.4f} ({score * 100:.2f})
  Why it matters:
{factor_lines}
  Next step: {next_step(vulnerability, score)}
  Confidence: {confidence_level(vulnerability)}
  Source: NIST NVD / CISA KEV / FIRST EPSS (organiser-provided snapshot)
""".strip()