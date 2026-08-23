import os
import requests

from models import Vulnerability

FEATHERLESS_BASE = "https://api.featherless.ai/v1"
MODEL = "mistralai/Mistral-Nemo-Instruct-2407"  # fast/efficient, fine for short phrasing


def _api_key_available() -> bool:
    return bool(os.environ.get("FEATHERLESS_API_KEY"))


def phrase_title(vulnerability: Vulnerability, fallback: str) -> str:
    """
    Rewrites the deterministic title into something a bit more natural.
    Only the vulnerability's own fields are given to the model — it cannot
    add facts, versions, dates, or remediation steps. Falls back to the
    deterministic template if the key isn't set or the call fails, so the
    demo never depends on this working.
    """

    if not _api_key_available():
        return fallback

    api_key = os.environ["FEATHERLESS_API_KEY"]

    system = (
        "You rewrite one vulnerability's plain-language title into a "
        "clearer, natural-sounding single sentence under 12 words. "
        "Use ONLY the facts given. Do not invent versions, vendors, dates, "
        "or fixes. Output the title only, nothing else."
    )

    user = (
        f"Product: {vulnerability.product_name}\n"
        f"Actively exploited (CISA KEV): {vulnerability.cisa_kev}\n"
        f"CVSS severity: {vulnerability.cvss_base_score}/10\n"
        f"Current title: {fallback}"
    )

    try:
        response = requests.post(
            f"{FEATHERLESS_BASE}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": 40,
                "temperature": 0.2,
            },
            timeout=8,
        )

        if response.status_code != 200:
            return fallback

        text = response.json()["choices"][0]["message"]["content"].strip()
        return text if text else fallback

    except Exception:
        # Network issue, 429 (rate limit), 503 (cold model) — always fall back
        return fallback