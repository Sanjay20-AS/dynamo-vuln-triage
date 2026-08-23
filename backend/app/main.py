from data_loader import load_vulnerabilities, load_profiles
from matcher import match_vulnerabilities
from scorer import rank_vulnerabilities
from explainer import render_result_card

vulnerabilities = load_vulnerabilities(
    "../../data/vulnerabilities.csv"
)

profiles = load_profiles(
    "../../data/profiles.json"
)


for profile in profiles:

    matched = match_vulnerabilities(
        vulnerabilities,
        profile
    )

    ranked = rank_vulnerabilities(
        matched,
        profile
    )

    print("\n" + "=" * 60)
    print(profile.name)
    print("=" * 60)

    for rank, (vulnerability, score) in enumerate(
        ranked[:5],
        start=1
    ):

        print(f"\n{rank}. " + render_result_card(vulnerability, profile, score))