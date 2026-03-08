"""
Script de simulation LLM.

Ce script :
1. initialise la base si besoin
2. récupère les vulnérabilités non analysées
3. génère une fausse analyse
4. sauvegarde le résultat dans la base
5. affiche le résultat

Ce script permet de tester l'intégration du module LLM
sans clé API ni service externe.
"""

from services.repository import (
    init_db,
    get_unanalyzed_vulnerabilities,
    save_llm_analysis,
    get_analysis_by_cve_id
)
from services.llm_simulator import generate_fake_llm_analysis


def main():
    """
    Point d'entrée principal du script.
    """

    init_db()

    vulnerabilities = get_unanalyzed_vulnerabilities(limit=5)

    if not vulnerabilities:
        print("Aucune vulnérabilité à analyser. Tout est déjà traité.")
        return

    print(f"{len(vulnerabilities)} vulnérabilités à analyser.\n")

    for vuln in vulnerabilities:
        cve_id = vuln["cve_id"]
        print(f"Analyse simulée de {cve_id}...")

        analysis = generate_fake_llm_analysis(vuln)

        save_llm_analysis(
            cve_id=cve_id,
            summary=analysis["summary"],
            impact=analysis["impact"],
            mitigation=analysis["mitigation"]
        )

        saved = get_analysis_by_cve_id(cve_id)

        print("Résumé sauvegardé :")
        print(saved["llm_summary"])
        print("-" * 80)

    print("\nSimulation terminée avec succès.")


if __name__ == "__main__":
    main()