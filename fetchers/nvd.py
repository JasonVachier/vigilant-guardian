"""
Fetcher NVD

Ce module est responsable de récupérer les vulnérabilités
depuis l'API officielle NVD (National Vulnerability Database).

Documentation API :
https://nvd.nist.gov/developers/vulnerabilities
"""

import requests

from config import NVD_API_URL, FETCH_LIMIT, HTTP_TIMEOUT


def fetch_nvd_latest():
    """
    Récupère les vulnérabilités les plus récentes depuis l'API NVD.

    Returns
    -------
    list
        Liste des vulnérabilités retournées par l'API NVD
    """

    # paramètres envoyés à l'API
    params = {
        "resultsPerPage": FETCH_LIMIT
    }

    try:
        # appel API
        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=HTTP_TIMEOUT
        )

        # vérifie si la requête a réussi
        response.raise_for_status()

        data = response.json()

        # extrait les vulnérabilités
        vulnerabilities = data.get("vulnerabilities", [])

        return vulnerabilities

    except requests.exceptions.RequestException as e:
        print("Erreur lors de la récupération des vulnérabilités NVD")
        print(e)
        return []