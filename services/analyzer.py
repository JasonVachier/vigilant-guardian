"""
Module d'analyse LLM des vulnérabilités (Personne 2).

Responsabilités :
- récupérer les vulnérabilités non analysées
- construire un prompt structuré
- appeler un modèle LLM (ou le simulateur)
- parser la réponse JSON
- sauvegarder l'analyse via repository.save_llm_analysis

Ce module peut fonctionner :
1) avec un vrai LLM (OpenAI) si USE_REAL_LLM = True
2) avec le simulateur interne pour les tests (par défaut)
"""

import json
import time
import logging

from services.repository import (
    get_unanalyzed_vulnerabilities,
    save_llm_analysis,
)
from services.llm_simulator import generate_fake_llm_analysis

# ---------------------------------------------------
# Configuration
# ---------------------------------------------------

USE_REAL_LLM = False   # passer à True quand l'API est prête
MAX_RETRIES = 3
RETRY_DELAY = 3

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ---------------------------------------------------
# Construction du prompt
# ---------------------------------------------------

def build_prompt(vuln):
    """
    Construit le prompt envoyé au LLM.
    Utilise uniquement les champs disponibles dans la base.
    """
    prompt = f"""
Tu es un analyste en cybersécurité défensive.
Analyse la vulnérabilité suivante et produis une synthèse
claire et utile pour une équipe sécurité.

Informations disponibles :
CVE ID: {vuln["cve_id"]}
Date publication: {vuln["published_date"]}
Score CVSS: {vuln["cvss_score"]}
Sévérité: {vuln["severity"]}
KEV (exploitation active connue): {vuln["kev"]}
Vendor: {vuln["vendor"]}
Product: {vuln["product"]}

Description:
{vuln["description_raw"]}

Références:
{vuln["references_json"]}

Instructions :
- Ne pas inventer d'information absente
- Si une donnée manque écrire "non précisé"
- Analyse uniquement défensive

Produis une sortie STRICTEMENT JSON au format :
{{
  "summary": "...",
  "impact": "...",
  "mitigation": "...",
  "priority": "Haute | Moyenne | Basse"
}}
"""
    return prompt


# ---------------------------------------------------
# Appel LLM
# ---------------------------------------------------

def call_llm(prompt, vuln):
    """
    Appelle le LLM ou le simulateur selon la configuration.
    """
    if not USE_REAL_LLM:
        return generate_fake_llm_analysis(vuln)

    try:
        from openai import OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Tu es un expert en cybersécurité défensive."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        text = response.choices[0].message.content
        return json.loads(text)
    except Exception as e:
        raise RuntimeError(f"Erreur appel LLM: {e}")


# ---------------------------------------------------
# Parsing sécurisé
# ---------------------------------------------------

def parse_llm_output(output):
    """
    Valide et extrait les champs de la sortie LLM.
    Retourne (summary, impact, mitigation).
    """
    if not isinstance(output, dict):
        raise ValueError("Sortie LLM invalide : dict attendu")

    summary = output.get("summary", "non précisé")
    impact = output.get("impact", "non précisé")
    mitigation = output.get("mitigation", "non précisé")

    return summary, impact, mitigation


# ---------------------------------------------------
# Analyse principale
# ---------------------------------------------------

def analyze_vulnerabilities(limit=10):
    """
    Analyse un batch de vulnérabilités non encore traitées.

    Étapes :
    1. Récupérer les vulnérabilités où llm_analyzed = 0
    2. Construire le prompt pour chacune
    3. Appeler le LLM (ou simulateur)
    4. Parser la sortie
    5. Sauvegarder via save_llm_analysis()
    """
    vulnerabilities = get_unanalyzed_vulnerabilities(limit)

    if not vulnerabilities:
        logger.info("Aucune vulnérabilité à analyser.")
        return

    logger.info(f"{len(vulnerabilities)} vulnérabilité(s) à analyser")

    for vuln in vulnerabilities:
        cve_id = vuln["cve_id"]
        logger.info(f"Analyse de {cve_id}...")

        prompt = build_prompt(vuln)

        for attempt in range(MAX_RETRIES):
            try:
                result = call_llm(prompt, vuln)
                summary, impact, mitigation = parse_llm_output(result)

                save_llm_analysis(
                    cve_id=cve_id,
                    summary=summary,
                    impact=impact,
                    mitigation=mitigation,
                )

                logger.info(f"  ✓ {cve_id} analysé avec succès")
                break

            except Exception as e:
                logger.warning(
                    f"  ⚠ Erreur {cve_id} (tentative {attempt + 1}/{MAX_RETRIES}) : {e}"
                )
                if attempt + 1 == MAX_RETRIES:
                    logger.error(f"  ✗ Échec définitif pour {cve_id}")
                else:
                    time.sleep(RETRY_DELAY)
