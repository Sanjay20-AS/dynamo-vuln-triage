from models import Vulnerability, OrganizationProfile

CRITICAL_PRODUCT_BOOST = 0.20  # visible, tunable — document this in README


def calculate_score(
    vulnerability: Vulnerability,
    profile: OrganizationProfile
) -> float:

    # Convert CVSS from 0-10 to 0-1
    cvss = vulnerability.cvss_base_score / 10

    # Convert KEV True/False to 1/0
    kev = 1.0 if vulnerability.cisa_kev else 0.0

    # EPSS is already between 0 and 1
    epss = vulnerability.first_epss

    weights = profile.weights

    score = (
        cvss * weights.cvss
        + kev * weights.cisa_kev
        + epss * weights.first_epss
    )

    if vulnerability.is_critical_product:
        score += CRITICAL_PRODUCT_BOOST

    if profile.exposure == 'internet-facing':
        score += 0.10
    elif profile.exposure == 'internal':
        score -= 0.05

    if profile.importance == 'critical':
        score += 0.15
    elif profile.importance == 'high':
        score += 0.05

    return score


def rank_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    profile: OrganizationProfile
) -> list[tuple[Vulnerability, float]]:

    scored = []

    for vulnerability in vulnerabilities:

        score = calculate_score(
            vulnerability,
            profile
        )

        scored.append((vulnerability, score))

    scored.sort(
        key=lambda item: item[1],
        reverse=True
    )

    return scored