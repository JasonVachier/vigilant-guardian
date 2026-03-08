"""
Normalisation des vulnérabilités.

Ce module transforme les données provenant de différentes
sources (NVD, CISA) en un format standard utilisé par tout le projet.
"""

import json


def _extract_english_description(descriptions: list) -> str:
    """
    Retourne la description anglaise si elle existe.
    Sinon, retourne la première description disponible.
    """

    if not descriptions:
        return "Non précisé"

    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "Non précisé")

    return descriptions[0].get("value", "Non précisé")


def _extract_references(references: list) -> str:
    """
    Extrait les URLs de référence et les stocke en JSON texte.
    """

    urls = []

    for ref in references:
        url = ref.get("url")
        if url:
            urls.append(url)

    return json.dumps(urls)


def _extract_cvss_from_nvd_metrics(metrics: dict) -> tuple[float | None, str]:
    """
    Extrait le score CVSS et la sévérité depuis les métriques NVD.

    Ordre de priorité :
    1. CVSS v4.0
    2. CVSS v3.1
    3. CVSS v3.0
    4. CVSS v2.0

    Retour
    ------
    tuple(score, severity)
    """

    # -----------------------------
    # CVSS v4.0
    # -----------------------------
    if metrics.get("cvssMetricV40"):
        metric = metrics["cvssMetricV40"][0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "Unknown"

        return score, severity

    # -----------------------------
    # CVSS v3.1
    # -----------------------------
    if metrics.get("cvssMetricV31"):
        metric = metrics["cvssMetricV31"][0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "Unknown"

        return score, severity

    # -----------------------------
    # CVSS v3.0
    # -----------------------------
    if metrics.get("cvssMetricV30"):
        metric = metrics["cvssMetricV30"][0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "Unknown"

        return score, severity

    # -----------------------------
    # CVSS v2.0
    # -----------------------------
    if metrics.get("cvssMetricV2"):
        metric = metrics["cvssMetricV2"][0]
        cvss_data = metric.get("cvssData", {})

        score = cvss_data.get("baseScore")
        severity = metric.get("baseSeverity") or "Unknown"

        return score, severity

    # -----------------------------
    # aucun score disponible
    # -----------------------------
    return None, "Unknown"


def normalize_nvd_item(item: dict) -> dict:
    """
    Convertit une vulnérabilité NVD brute en format standard.
    """

    cve = item.get("cve", {})

    cve_id = cve.get("id", "UNKNOWN")
    description = _extract_english_description(cve.get("descriptions", []))
    references = _extract_references(cve.get("references", []))
    metrics = cve.get("metrics", {})

    cvss_score, severity = _extract_cvss_from_nvd_metrics(metrics)

    published_date = cve.get("published", "")[:10]

    normalized = {
        "cve_id": cve_id,
        "title": cve_id,
        "published_date": published_date,
        "cvss_score": cvss_score,
        "severity": severity,
        "kev": False,
        "source": "NVD",
        "vendor": None,
        "product": None,
        "description_raw": description,
        "references": references
    }

    return normalized


def normalize_cisa_item(item: dict) -> dict:
    """
    Convertit une vulnérabilité CISA KEV en format standard.
    """

    cve_id = item.get("cveID", "UNKNOWN")
    vendor = item.get("vendorProject")
    product = item.get("product")
    description = item.get("shortDescription", "Non précisé")
    published_date = item.get("dateAdded", "")

    normalized = {
        "cve_id": cve_id,
        "title": cve_id,
        "published_date": published_date,
        "cvss_score": None,
        "severity": "Unknown",
        "kev": True,
        "source": "CISA-KEV",
        "vendor": vendor,
        "product": product,
        "description_raw": description,
        "references": json.dumps([])
    }

    return normalized