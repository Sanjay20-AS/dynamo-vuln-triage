import csv
import json

from models import (
    Vulnerability,
    OrganizationProfile,
    ProfileWeights
)


def load_vulnerabilities(path: str) -> list[Vulnerability]:

    vulnerabilities = []

    with open(path, newline="", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        for row in reader:

            vulnerability = Vulnerability(
                cve_id=row["cve_id"],
                product_name=row["product_name"],
                cvss_base_score=float(row["cvss_base_score"]),
                cisa_kev=row["cisa_kev"].strip().lower() == "true",
                first_epss=float(row["first_epss"])
            )

            vulnerabilities.append(vulnerability)

    return vulnerabilities


def load_profiles(path: str) -> list[OrganizationProfile]:

    with open(path, encoding="utf-8") as file:

        data = json.load(file)

    profiles = []

    for profile in data["organizations"]:

        weights = ProfileWeights(
            cvss=profile["weight_modifiers"]["cvss_weight"],
            cisa_kev=profile["weight_modifiers"]["cisa_kev_weight"],
            first_epss=profile["weight_modifiers"]["first_epss_weight"]
        )

        organization = OrganizationProfile(
            org_id=profile["org_id"],
            name=profile["name"],
            sector=profile["sector"],
            risk_appetite=profile["risk_appetite"],
            exposure=profile.get("exposure", "internal"),
            importance=profile.get("importance", "normal"),
            weights=weights,
            critical_products=profile["critical_products"]
        )

        profiles.append(organization)

    return profiles