"""
Simulateur d'analyse LLM.

Ce module ne fait pas appel à une vraie intelligence artificielle.
Il génère simplement des textes automatiques à partir des données
déjà présentes dans la base.

Objectif :
- tester l'intégration du futur module LLM
- vérifier que les champs llm_* sont bien sauvegardés
- permettre au front-end d'afficher des résultats
"""

def generate_fake_llm_analysis(vulnerability) -> dict:
    """
    Génère une fausse analyse pour une vulnérabilité.

    Parameters
    ----------
    vulnerability : sqlite3.Row ou dict-like
        Vulnérabilité lue depuis la base

    Returns
    -------
    dict
        Dictionnaire contenant summary, impact et mitigation
    """

    cve_id = vulnerability["cve_id"]
    severity = vulnerability["severity"] or "Unknown"
    vendor = vulnerability["vendor"] or "éditeur non précisé"
    product = vulnerability["product"] or "produit non précisé"
    description = vulnerability["description_raw"] or "Description non précisée"
    kev = "oui" if vulnerability["kev"] else "non"

    summary = (
        f"La vulnérabilité {cve_id} affecte {product} chez {vendor}. "
        f"Le niveau de sévérité actuellement enregistré est {severity}. "
        f"Elle est marquée comme activement exploitée : {kev}. "
        f"Résumé technique disponible : {description}"
    )

    impact = (
        f"Cette vulnérabilité peut représenter un risque important pour les systèmes "
        f"utilisant {product}. Une exploitation réussie pourrait compromettre la "
        f"confidentialité, l'intégrité ou la disponibilité du système selon le contexte. "
        f"Le niveau de priorité de traitement doit être ajusté selon la sévérité "
        f"et le statut KEV."
    )

    mitigation = (
        f"Il est recommandé de surveiller les correctifs liés à {cve_id}, "
        f"d'appliquer les mises à jour de sécurité disponibles, de limiter l'exposition "
        f"des services concernés, de renforcer la supervision, et de prioriser cette "
        f"vulnérabilité si elle touche un système critique."
    )

    return {
        "summary": summary,
        "impact": impact,
        "mitigation": mitigation
    }