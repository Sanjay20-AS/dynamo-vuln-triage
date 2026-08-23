from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from data_loader import load_vulnerabilities, load_profiles
from matcher import match_vulnerabilities
from scorer import rank_vulnerabilities
from explainer import (
    priority_label,
    plain_language_title,
    next_step,
    confidence_level,
    explain_factors,
)
from negative_test import find_negative_test  # reuse your existing logic


app = FastAPI(title="Personalised Vulnerability Triage API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load once at startup — the brief uses a frozen data pack, no live reload needed
VULNERABILITIES = load_vulnerabilities("../../data/vulnerabilities.csv")
PROFILES = load_profiles("../../data/profiles.json")
PROFILES_BY_ID = {p.org_id: p for p in PROFILES}


def _card(vulnerability, profile, score) -> dict:
    return {
        "cve_id": vulnerability.cve_id,
        "priority": priority_label(score),
        "title": plain_language_title(vulnerability),
        "product": vulnerability.product_name,
        "score": round(score, 4),
        "score_display": round(score * 100, 2),
        "is_critical_product": vulnerability.is_critical_product,
        "factors": [
            {"label": name, "value": val}
            for name, val in explain_factors(vulnerability, profile)
        ],
        "next_step": next_step(vulnerability, score),
        "confidence": confidence_level(vulnerability),
        "cvss": vulnerability.cvss_base_score,
        "kev": vulnerability.cisa_kev,
        "epss": vulnerability.first_epss,
        "source": "NIST NVD / CISA KEV / FIRST EPSS (organiser-provided snapshot)",
    }


@app.get("/organizations")
def get_organizations():
    return [
        {
            "org_id": p.org_id,
            "name": p.name,
            "sector": p.sector,
            "risk_appetite": p.risk_appetite,
            "exposure": p.exposure,
            "importance": p.importance,
            "weights": {
                "cvss": p.weights.cvss,
                "cisa_kev": p.weights.cisa_kev,
                "first_epss": p.weights.first_epss,
            },
            "critical_products": p.critical_products,
        }
        for p in PROFILES
    ]


@app.get("/triage/{org_id}")
def get_triage(org_id: str):
    profile = PROFILES_BY_ID.get(org_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Unknown org_id: {org_id}")

    matched = match_vulnerabilities(list(VULNERABILITIES), profile)
    ranked = rank_vulnerabilities(matched, profile)
    top5 = ranked[:5]

    return {
        "organization": profile.name,
        "org_id": profile.org_id,
        "results": [_card(v, profile, score) for v, score in top5],
    }


@app.get("/triage/{org_id}/negative-test")
def get_negative_test(org_id: str):
    profile = PROFILES_BY_ID.get(org_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Unknown org_id: {org_id}")

    matched = match_vulnerabilities(list(VULNERABILITIES), profile)
    ranked = rank_vulnerabilities(matched, profile)

    top5_ids = {v.cve_id for v, score in ranked[:5]}
    candidates = [
        (v, score) for v, score in ranked
        if v.cvss_base_score >= 9.0 and v.cve_id not in top5_ids
    ]
    if not candidates:
        raise HTTPException(status_code=404, detail="No negative test example found")

    candidates.sort(key=lambda item: item[1])
    vulnerability, score = candidates[0]

    return {
        "cve_id": vulnerability.cve_id,
        "cvss": vulnerability.cvss_base_score,
        "product": vulnerability.product_name,
        "is_critical_product": vulnerability.is_critical_product,
        "kev": vulnerability.cisa_kev,
        "epss": vulnerability.first_epss,
        "score": round(score, 4),
        "score_display": round(score * 100, 2),
        "explanation": (
            f"CVSS {vulnerability.cvss_base_score} is high, but this item scored "
            f"only {score*100:.2f} and did not make the top 5 — "
            f"{'not critical, ' if not vulnerability.is_critical_product else ''}"
            f"{'not in KEV, ' if not vulnerability.cisa_kev else ''}"
            f"EPSS {vulnerability.epss:.1%}."
        ) if hasattr(vulnerability, "epss") else (
            f"CVSS {vulnerability.cvss_base_score} is high, but this item scored "
            f"only {score*100:.2f} and did not make the top 5 — "
            f"{'not critical, ' if not vulnerability.is_critical_product else ''}"
            f"{'not in KEV, ' if not vulnerability.cisa_kev else ''}"
            f"EPSS {vulnerability.first_epss:.1%}."
        ),
    }