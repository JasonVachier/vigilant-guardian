"""
Module d'analyse LLM des vulnérabilités (Personne 2).

Responsabilités :
- récupérer les vulnérabilités non analysées (sqlite3.Row → dict)
- construire un prompt structuré
- appeler Google Gemini via le SDK google-genai (ou le simulateur si clé absente)
- parser la réponse JSON
- sauvegarder l'analyse via repository.save_llm_analysis

Comportement selon la configuration :
- GEMINI_API_KEY présente dans l'env/.env → appel API Gemini réel (gemini-2.0-flash)
- Clé absente → simulateur interne (aucun crash)
"""

import json
import time
import os
import re
import logging

from dotenv import load_dotenv

from services.repository import get_unanalyzed_vulnerabilities, save_llm_analysis
from services.llm_simulator import generate_fake_llm_analysis

load_dotenv()

# ---------------------------------------------------
# Configuration
# ---------------------------------------------------

# Auto-détecte la présence de la clé Gemini
USE_REAL_LLM = bool(os.environ.get("GEMINI_API_KEY"))
GEMINI_MODEL = "gemini-2.5-flash-lite"
MAX_RETRIES = 3
RETRY_DELAY = 3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------
# Utilitaires
# ---------------------------------------------------

def _to_dict(vuln) -> dict:
    """Convertit un sqlite3.Row en dict si nécessaire."""
    if isinstance(vuln, dict):
        return vuln
    return dict(vuln)


# ---------------------------------------------------
# Construction du prompt
# ---------------------------------------------------

def build_prompt(vuln: dict) -> str:
    """
    Construit le prompt envoyé à Gemini.
    Les instructions système sont intégrées au prompt (Gemini n'a pas de rôle "system" séparé).
    Attend un dict — appeler _to_dict() avant si nécessaire.
    """
    exploitation = "Oui — répertoriée dans le catalogue CISA KEV (exploitation active connue)" \
        if vuln.get("kev") else "Non répertoriée dans le catalogue CISA KEV"

    return f"""Tu es un analyste expert en cybersécurité défensive.
Ta mission : analyser des vulnérabilités CVE et produire des synthèses opérationnelles en français
pour aider une équipe de sécurité à prioriser et corriger les failles.

Règles strictes :
- Réponds UNIQUEMENT en JSON valide, sans texte avant ni après le bloc JSON.
- N'invente aucune information absente des données fournies.
- Si une donnée est manquante, utilise la valeur "non précisé".
- Adopte une perspective défensive et orientée remédiation.
- Rédige en français.

--- Données de la vulnérabilité ---
CVE ID              : {vuln.get("cve_id", "non précisé")}
Date de publication : {vuln.get("published_date", "non précisé")}
Score CVSS          : {vuln.get("cvss_score", "non précisé")}
Sévérité            : {vuln.get("severity", "non précisé")}
Exploitation active : {exploitation}
Vendor              : {vuln.get("vendor", "non précisé")}
Produit             : {vuln.get("product", "non précisé")}

Description technique :
{vuln.get("description_raw", "non précisé")}
--- Fin des données ---

Produis UNIQUEMENT le JSON suivant, sans aucun texte supplémentaire :
{{
  "summary": "Résumé technique en 2-3 phrases expliquant la nature de la faille",
  "impact": "Impact potentiel sur les systèmes, données et continuité de service",
  "mitigation": "Actions de remédiation concrètes, priorisées et applicables immédiatement",
  "priority": "Haute | Moyenne | Basse"
}}"""


# ---------------------------------------------------
# Appel LLM (Gemini)
# ---------------------------------------------------

def call_llm(prompt: str, vuln: dict):
    """
    Appelle Google Gemini si GEMINI_API_KEY est disponible,
    sinon bascule silencieusement sur le simulateur interne.
    Retourne soit une str (texte JSON brut de Gemini) soit un dict (simulateur).
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    if not USE_REAL_LLM or not api_key:
        logger.info("Mode simulateur actif (GEMINI_API_KEY absente ou USE_REAL_LLM=False)")
        return generate_fake_llm_analysis(vuln)

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=1024,
            ),
        )
        return response.text

    except Exception as e:
        logger.warning(f"Erreur Gemini API ({e}) — basculement simulateur")
        return generate_fake_llm_analysis(vuln)


# ---------------------------------------------------
# Parsing sécurisé
# ---------------------------------------------------

def extract_json(text: str) -> dict:
    """
    Extrait le premier objet JSON trouvé dans une chaîne.
    Gemini peut parfois entourer le JSON de balises markdown ```json ... ```.
    """
    # Retire les blocs markdown si présents
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError("Aucun objet JSON trouvé dans la réponse Gemini")
    return json.loads(match.group())


def parse_llm_output(output) -> tuple:
    """
    Extrait (summary, impact, mitigation) depuis la sortie LLM.
    Accepte un dict (simulateur) ou une str (réponse Gemini brute).
    """
    if isinstance(output, dict):
        data = output
    else:
        data = extract_json(output)

    summary = data.get("summary") or "non précisé"
    impact = data.get("impact") or "non précisé"
    mitigation = data.get("mitigation") or "non précisé"

    return summary, impact, mitigation


# ---------------------------------------------------
# Analyse principale
# ---------------------------------------------------

def analyze_vulnerabilities(limit: int = 10) -> dict:
    """
    Analyse un batch de vulnérabilités non encore traitées.

    Étapes :
    1. Récupère les vulnérabilités où llm_analyzed = 0 (KEV et CVSS élevé en priorité)
    2. Convertit chaque sqlite3.Row en dict (_to_dict)
    3. Construit le prompt, appelle Gemini (ou simulateur)
    4. Parse la sortie JSON et sauvegarde via save_llm_analysis()

    Retourne un dict de statistiques : {total, analyzed, failed}
    """
    rows = get_unanalyzed_vulnerabilities(limit)

    stats = {"total": len(rows), "analyzed": 0, "failed": 0}

    if not rows:
        logger.info("Aucune vulnérabilité à analyser.")
        return stats

    logger.info(f"{len(rows)} vulnérabilité(s) à analyser via {'Gemini' if USE_REAL_LLM else 'simulateur'}")

    for row in rows:
        vuln = _to_dict(row)
        cve_id = vuln["cve_id"]
        logger.info(f"Analyse de {cve_id}...")

        prompt = build_prompt(vuln)
        success = False

        for attempt in range(MAX_RETRIES):
            try:
                raw_output = call_llm(prompt, vuln)
                summary, impact, mitigation = parse_llm_output(raw_output)

                save_llm_analysis(
                    cve_id=cve_id,
                    summary=summary,
                    impact=impact,
                    mitigation=mitigation,
                )

                logger.info(f"  ✓ {cve_id} analysé avec succès")
                stats["analyzed"] += 1
                success = True
                break

            except Exception as e:
                logger.warning(
                    f"  ⚠ Erreur {cve_id} (tentative {attempt + 1}/{MAX_RETRIES}) : {e}"
                )
                if attempt + 1 < MAX_RETRIES:
                    time.sleep(RETRY_DELAY)

        if not success:
            logger.error(f"  ✗ Échec définitif pour {cve_id}")
            stats["failed"] += 1

    logger.info(
        f"Analyse terminée — {stats['analyzed']} succès, "
        f"{stats['failed']} échec(s) sur {stats['total']} vulnérabilité(s)"
    )
    return stats
