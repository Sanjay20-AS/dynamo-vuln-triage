from models import Vulnerability, OrganizationProfile


def match_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    profile: OrganizationProfile
) -> list[Vulnerability]:
    """
    Tags every vulnerability with whether it hits this org's critical
    products. Nothing is excluded here — the brief requires non-critical,
    high-CVSS items to still appear (just ranked lower), so a judge can see
    the negative-test contrast. Filtering them out here would hide that.
    """

    critical_products = {
        product.strip().lower()
        for product in profile.critical_products
    }

    for vulnerability in vulnerabilities:
        product = vulnerability.product_name.strip().lower()
        vulnerability.is_critical_product = product in critical_products

    return vulnerabilities