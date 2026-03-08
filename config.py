"""
Configuration globale du projet Vigilant Guardian

Ce fichier centralise tous les paramètres utilisés dans le projet.

Pourquoi ?
- éviter de répéter des valeurs partout
- faciliter les modifications
- rendre le projet plus lisible
"""

from pathlib import Path


# ---------------------------------------------------
# Chemins du projet
# ---------------------------------------------------

# Dossier racine du projet
BASE_DIR = Path(__file__).resolve().parent

# Dossier qui contiendra les données (base SQLite)
DATA_DIR = BASE_DIR / "data"

# Chemin vers la base de données SQLite
DB_PATH = DATA_DIR / "vulnerabilities.db"


# ---------------------------------------------------
# APIs utilisées
# ---------------------------------------------------

# API officielle NVD (National Vulnerability Database)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Catalogue des vulnérabilités exploitées activement
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------
# Paramètres de récupération
# ---------------------------------------------------

# Nombre maximum de vulnérabilités récupérées par requête
FETCH_LIMIT = 20

# Timeout des requêtes HTTP (en secondes)
HTTP_TIMEOUT = 30


# ---------------------------------------------------
# Paramètres de l'application
# ---------------------------------------------------

# Nombre d'éléments affichés par page dans l'interface
DEFAULT_RESULTS_PER_PAGE = 20