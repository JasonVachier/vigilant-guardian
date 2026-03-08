"""
Script de mise à jour des vulnérabilités.

Ce script :
1. initialise la base
2. récupère les vulnérabilités NVD
3. récupère les vulnérabilités CISA KEV
4. normalise les données
5. insère ou met à jour les vulnérabilités
6. affiche quelques statistiques utiles
"""

from fetchers.nvd import fetch_nvd_latest
from fetchers.cisa_kev import fetch_cisa_kev

from services.normalizer import normalize_nvd_item, normalize_cisa_item
from services.repository import (
    init_db,
    upsert_vulnerability,
    count_vulnerabilities,
    count_kev_vulnerabilities,
    get_recent_vulnerabilities,
    get_kev_vulnerabilities,
    get_vulnerabilities_by_severity,
    get_unanalyzed_vulnerabilities,
    get_analyzed_vulnerabilities
)


def main():
    """
    Point d'entrée principal du script.
    """

    init_db()

    nvd_count = 0
    kev_count = 0

    print("Récupération NVD...")
    nvd_items = fetch_nvd_latest()

    for item in nvd_items:
        vuln = normalize_nvd_item(item)
        upsert_vulnerability(vuln)
        nvd_count += 1

    print("Récupération CISA KEV...")
    kev_items = fetch_cisa_kev()

    for item in kev_items:
        vuln = normalize_cisa_item(item)
        upsert_vulnerability(vuln)
        kev_count += 1

    print("\nMise à jour terminée.")
    print(f"Entrées NVD traitées : {nvd_count}")
    print(f"Entrées CISA KEV traitées : {kev_count}")
    print(f"Nombre total de vulnérabilités uniques : {count_vulnerabilities()}")
    print(f"Nombre total de vulnérabilités KEV : {count_kev_vulnerabilities()}")

    print("\n5 vulnérabilités les plus récentes :")
    for row in get_recent_vulnerabilities(5):
        print(
            row["cve_id"],
            "-",
            row["published_date"],
            "-",
            row["severity"],
            "- KEV:",
            row["kev"]
        )

    print("\n5 vulnérabilités KEV :")
    for row in get_kev_vulnerabilities(5):
        print(
            row["cve_id"],
            "-",
            row["published_date"],
            "-",
            row["severity"],
            "- Source:",
            row["source"]
        )

    print("\n5 vulnérabilités Critical :")
    for row in get_vulnerabilities_by_severity("Critical", 5):
        print(
            row["cve_id"],
            "-",
            row["published_date"],
            "- KEV:",
            row["kev"]
        )

    print("\n5 vulnérabilités non encore analysées par LLM :")
    for row in get_unanalyzed_vulnerabilities(5):
        print(
            row["cve_id"],
            "-",
            row["published_date"],
            "-",
            row["severity"],
            "- KEV:",
            row["kev"],
            "- analyzed:",
            row["llm_analyzed"]
        )

    print("\n5 vulnérabilités déjà analysées par LLM :")
    for row in get_analyzed_vulnerabilities(5):
        print(
            row["cve_id"],
            "- analyzed:",
            row["llm_analyzed"]
        )


if __name__ == "__main__":
    main()