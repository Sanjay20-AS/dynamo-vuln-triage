from dataclasses import dataclass


@dataclass
class Vulnerability:
    cve_id: str
    product_name: str
    cvss_base_score: float
    cisa_kev: bool
    first_epss: float
    is_critical_product: bool = False   # <-- add this line


@dataclass
class ProfileWeights:
    cvss: float
    cisa_kev: float
    first_epss: float


@dataclass
class OrganizationProfile:
    org_id: str
    name: str
    sector: str
    risk_appetite: str
    exposure: str
    importance: str
    weights: ProfileWeights
    critical_products: list[str]