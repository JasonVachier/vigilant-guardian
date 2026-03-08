"""
Fetcher CISA KEV

Ce module récupère les vulnérabilités connues comme exploitées
dans la nature depuis le catalogue officiel CISA KEV.

Source :
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import requests

from config import CISA_KEV_URL, HTTP_TIMEOUT


def fetch_cisa_kev():
    """
    Récupère les vulnérabilités KEV depuis la CISA.

    Returns
    -------
    list
        liste des vulnérabilités KEV
    """

    try:

        response = requests.get(
            CISA_KEV_URL,
            timeout=HTTP_TIMEOUT
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        return vulnerabilities

    except requests.exceptions.RequestException as e:

        print("Erreur récupération CISA KEV")
        print(e)

        return []