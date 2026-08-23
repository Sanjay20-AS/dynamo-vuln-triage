import pandas as pd

from data_loader import load_vulnerabilities, load_profiles
from matcher import match_vulnerabilities
from scorer import rank_vulnerabilities


vulnerabilities = load_vulnerabilities(
    "../../data/vulnerabilities.csv"
)

# Add gold set vulnerabilities to the list to ensure they are ranked
gold_vulnerabilities = load_vulnerabilities("../../data/gold_set.csv")
vulnerabilities.extend(gold_vulnerabilities)

profiles = load_profiles(
    "../../data/profiles.json"
)

# Load the gold set
gold = pd.read_csv("../../data/gold_set.csv")


gold_cves = set(gold["cve_id"])


for profile in profiles:

    # Gold set only provides rankings for Bank and Startup
    if profile.org_id not in ["ORG-001", "ORG-002"]:
        continue

    matched = match_vulnerabilities(
        vulnerabilities,
        profile
    )

    ranked = rank_vulnerabilities(
        matched,
        profile
    )

    # Find ranks of gold vulnerabilities in the overall ranked list
    gold_ranked = []
    for rank_idx, (vulnerability, score) in enumerate(ranked, start=1):
        if vulnerability.cve_id in gold_cves:
            gold_ranked.append((rank_idx, vulnerability, score))

    print("\n" + "=" * 70)
    print(profile.name)
    print("=" * 70)

    print(
        f"{'Our Rank':<10}"
        f"{'CVE':<18}"
        f"{'Our Score':<12}"
        f"{'Gold Rank':<10}"
    )

    print("-" * 70)

    for our_rank, vulnerability, score in gold_ranked:

        gold_row = gold[
            gold["cve_id"] == vulnerability.cve_id
        ].iloc[0]

        if profile.org_id == "ORG-001":
            gold_rank = gold_row["practitioner_rank_bank"]
        else:
            gold_rank = gold_row["practitioner_rank_startup"]

        print(
            f"{our_rank:<10}"
            f"{vulnerability.cve_id:<18}"
            f"{score:<12.4f}"
            f"{int(gold_rank):<10}"
        )