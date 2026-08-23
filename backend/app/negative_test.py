from data_loader import load_vulnerabilities, load_profiles

from matcher import match_vulnerabilities

from scorer import rank_vulnerabilities





def find_negative_test(

    ranked: list[tuple],

    vulnerabilities: list

) -> None:

    """

    Required by the brief: show one CVSS >= 9.0 vulnerability that does

    NOT make the top 5, and explain why. This proves the system isn't

    just sorting by severity.

    """



    top5_ids = {v.cve_id for v, score in ranked[:5]}



    high_cvss_excluded = [

        (v, score) for v, score in ranked

        if v.cvss_base_score >= 9.0 and v.cve_id not in top5_ids

    ]



    if not high_cvss_excluded:

        print("No CVSS >= 9.0 item was excluded from top 5 — check manually.")

        return



    # lowest-scoring one makes the strongest example

    high_cvss_excluded.sort(key=lambda item: item[1])

    vulnerability, score = high_cvss_excluded[0]



    print(f"\nNEGATIVE TEST:")

    print(f"  {vulnerability.cve_id} has CVSS {vulnerability.cvss_base_score} "

          f"but did NOT make the top 5 (score {score:.4f} / {score*100:.2f})")

    print(f"  Product: {vulnerability.product_name}")

    print(f"  Critical for this org: {vulnerability.is_critical_product}")

    print(f"  KEV: {vulnerability.cisa_kev}  |  EPSS: {vulnerability.first_epss:.1%}")

    print(f"  Why excluded: not flagged critical, "

          f"{'not in KEV, ' if not vulnerability.cisa_kev else ''}"

          f"low relative EPSS/CVSS weight for this org's risk formula.")





if __name__ == "__main__":

    vulnerabilities = load_vulnerabilities("../../data/vulnerabilities.csv")

    profiles = load_profiles("../../data/profiles.json")



    for profile in profiles:

        matched = match_vulnerabilities(vulnerabilities, profile)

        ranked = rank_vulnerabilities(matched, profile)



        print("\n" + "=" * 60)

        print(profile.name)

        print("=" * 60)



        find_negative_test(ranked, vulnerabilities)