"""
llm_simulator.py — Simulation de sortie LLM (Personne 1)

Génère des analyses réalistes sans appeler un vrai LLM.
Utile pour tester la chaîne complète et pour la démonstration.
"""


def generate_fake_llm_analysis(vuln) -> dict:
    """
    Génère une fausse analyse LLM à partir des données d'une vulnérabilité.
    Retourne un dict avec summary, impact, mitigation, priority.

    Note : vuln peut être un dict OU un sqlite3.Row, on utilise donc
    l'accès par clé [] avec des valeurs par défaut via une conversion.
    """
    # Convertir sqlite3.Row en dict si nécessaire
    if not isinstance(vuln, dict):
        vuln = dict(vuln)

    cve_id = vuln.get("cve_id", "CVE-XXXX-XXXX")
    severity = vuln.get("severity") or "Unknown"
    vendor = vuln.get("vendor") or "non précisé"
    product = vuln.get("product") or "non précisé"
    kev = vuln.get("kev", 0)
    cvss = vuln.get("cvss_score")
    description = vuln.get("description_raw") or "non précisé"

    # Résumé basé sur les données existantes
    kev_text = " Cette vulnérabilité est activement exploitée (CISA KEV)." if kev else ""
    score_text = f" Score CVSS : {cvss}/10." if cvss else ""

    summary = (
        f"Vulnérabilité {severity} affectant {vendor} {product}. "
        f"{description[:150]}...{score_text}{kev_text}"
    )

    # Impact adapté à la sévérité
    impact_map = {
        "CRITICAL": f"Impact très élevé. Compromission potentielle complète des systèmes {product} de {vendor}. "
                    "Risque d'exécution de code à distance, vol de données ou déni de service majeur.",
        "HIGH": f"Impact élevé. Les systèmes {product} de {vendor} sont exposés à des attaques significatives. "
                "Exploitation possible pour élévation de privilèges ou accès non autorisé.",
        "MEDIUM": f"Impact modéré. Les systèmes {product} de {vendor} présentent un risque limité. "
                  "Exploitation nécessitant des conditions spécifiques.",
        "LOW": f"Impact faible. Risque limité pour les systèmes {product} de {vendor}.",
    }
    impact = impact_map.get(severity.upper(),
        f"Impact non évalué précisément pour {vendor} {product}. Sévérité : {severity}."
    )

    # Mitigation
    mitigation = (
        f"Vérifier la disponibilité d'un correctif auprès de {vendor}. "
        f"Appliquer les mises à jour de sécurité pour {product} dès que possible. "
    )
    if kev:
        mitigation += "URGENT : vulnérabilité activement exploitée — prioriser le déploiement du correctif. "
    if cvss and cvss >= 9.0:
        mitigation += "Isoler les systèmes vulnérables du réseau si le correctif n'est pas immédiatement applicable."

    # Priorité
    if kev or (cvss and cvss >= 9.0):
        priority = "Haute"
    elif cvss and cvss >= 7.0:
        priority = "Haute"
    elif cvss and cvss >= 4.0:
        priority = "Moyenne"
    else:
        priority = "Basse"

    return {
        "summary": summary,
        "impact": impact,
        "mitigation": mitigation,
        "priority": priority,
    }
