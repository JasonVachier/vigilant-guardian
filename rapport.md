# Rapport Technique — Vigilant Guardian
## Documentation de Référence Complète

> **Projet académique 2026** — Veille et analyse défensive des vulnérabilités CVE  
> **Stack** : Python 3.12 · Flask · SQLite · Google Gemini API · Bootstrap 5

---

## Table des matières

1. [Présentation Générale](#1-présentation-générale)
2. [Architecture Globale](#2-architecture-globale)
3. [Structure du Projet](#3-structure-du-projet)
4. [Documentation des Routes Backend](#4-documentation-des-routes-backend)
5. [Logique Métier et Services](#5-logique-métier-et-services)
6. [Interface Utilisateur](#6-interface-utilisateur)
7. [Procédures Techniques](#7-procédures-techniques)
8. [Variables d'Environnement](#8-variables-denvironnement)

---

## 1. Présentation Générale

### 1.1 Objectif

**Vigilant Guardian** est une application web de cybersécurité défensive permettant à une équipe de sécurité de :

- **Collecter** automatiquement les vulnérabilités CVE publiées par le NIST (NVD) et les menaces activement exploitées référencées par la CISA (catalogue KEV).
- **Analyser** chaque vulnérabilité via un modèle de langage (Google Gemini) pour produire un résumé technique, une évaluation d'impact et des recommandations de remédiation en français.
- **Visualiser** les résultats dans un tableau de bord web filtrable, avec des fiches de détail enrichies par l'IA.

### 1.2 Contexte de développement

Le projet a été réalisé en collaboration par trois développeurs aux responsabilités distinctes :

| Contributeur | Périmètre |
|---|---|
| **Personne 1** | Socle technique, fetchers NVD/CISA, normalisation, simulateur LLM |
| **Personne 2** | Module d'analyse LLM (`analyzer.py`), script batch (`analyze_new.py`) |
| **Personne 3** | Interface web Flask, templates Jinja2, repository SQL, statistiques |

---

## 2. Architecture Globale

```
┌─────────────────────────────────────────────────────┐
│                   SOURCES DE DONNÉES                 │
│   NVD API (NIST)          CISA KEV (JSON feed)       │
└──────────────┬────────────────────┬─────────────────┘
               │                    │
               ▼                    ▼
┌─────────────────────────────────────────────────────┐
│                    COUCHE COLLECTE                   │
│   fetchers/nvd.py         fetchers/cisa_kev.py       │
└──────────────────────────┬──────────────────────────┘
                           │ données brutes (JSON)
                           ▼
┌─────────────────────────────────────────────────────┐
│                  COUCHE NORMALISATION                │
│              services/normalizer.py                 │
│    → format unifié dict (modèle Vulnerability)      │
└──────────────────────────┬──────────────────────────┘
                           │ dicts normalisés
                           ▼
┌─────────────────────────────────────────────────────┐
│                  COUCHE PERSISTANCE                  │
│              services/repository.py                 │
│              data/vulnerabilities.db (SQLite)        │
└──────────────┬────────────────────┬─────────────────┘
               │                    │
               ▼                    ▼
┌──────────────────────┐  ┌────────────────────────────┐
│  COUCHE ANALYSE IA   │  │    COUCHE PRÉSENTATION     │
│  services/analyzer   │  │    app.py (Flask)           │
│  Google Gemini API   │  │    templates/ (Jinja2)      │
│  (fallback simulateur│  │    static/ (CSS/JS)         │
└──────────────────────┘  └────────────────────────────┘
```

### 2.1 Flux de données principal

```
[Script update_data.py]
        │
        ├─► fetch_nvd_latest()   ──► normalize_nvd_item()   ──┐
        │                                                      ├─► upsert_vulnerability() ──► SQLite
        └─► fetch_cisa_kev()     ──► normalize_cisa_item()  ──┘

[Script analyze_new.py  /  Route POST /admin/analyze]
        │
        └─► get_unanalyzed_vulnerabilities()
                    │
                    └─► build_prompt()  ──► Gemini API  ──► parse_llm_output()
                                                │
                                                └─► save_llm_analysis()  ──► SQLite

[Navigateur  ──►  app.py  ──►  repository.py  ──►  SQLite  ──►  template Jinja2]
```

---

## 3. Structure du Projet

```
vigilant-guardian/
│
├── app.py                    # Application Flask — routes et helpers
├── config.py                 # Configuration centralisée (URLs, chemins, clés)
├── requirements.txt          # Dépendances Python
├── .env                      # Variables d'environnement (non versionné)
├── rapport.md                # Ce document
│
├── fetchers/                 # Couche collecte — appels HTTP aux APIs externes
│   ├── nvd.py                # Récupération NVD (NIST)
│   └── cisa_kev.py           # Récupération CISA KEV
│
├── services/                 # Couche métier — logique centrale
│   ├── normalizer.py         # Transformation données brutes → format unifié
│   ├── repository.py         # Accès SQLite (CRUD, recherche, stats)
│   ├── analyzer.py           # Analyse LLM via Google Gemini
│   └── llm_simulator.py      # Simulateur de sortie LLM (mode hors-ligne)
│
├── models/                   # Modèles de données
│   └── vulnerability.py      # Dataclass Vulnerability (contrat de données)
│
├── scripts/                  # Scripts d'administration en ligne de commande
│   ├── update_data.py        # Synchronisation des données depuis NVD + CISA
│   └── analyze_new.py        # Analyse batch des vulnérabilités non traitées
│
├── templates/                # Templates HTML Jinja2
│   ├── base.html             # Layout de base (navbar, footer, assets)
│   ├── index.html            # Tableau de bord principal
│   ├── detail.html           # Fiche détaillée d'une CVE
│   └── 404.html              # Page d'erreur personnalisée
│
├── static/                   # Assets statiques servis par Flask
│   ├── style.css             # Thème sombre cybersécurité (variables CSS + Bootstrap)
│   └── app.js                # Interactions client (tri, navigation, raccourcis)
│
└── data/                     # Données persistantes (créé automatiquement)
    └── vulnerabilities.db    # Base SQLite (générée à l'initialisation)
```

### 3.1 Rôle détaillé de chaque couche

| Dossier | Responsabilité | Dépendances |
|---|---|---|
| `fetchers/` | Appels HTTP aux APIs externes, retourne le JSON brut | `requests`, `config.py` |
| `services/` | Toute la logique métier (normalisation, BDD, IA) | `sqlite3`, `google-genai`, `dotenv` |
| `models/` | Contrat de données partagé (dataclass) | aucune |
| `scripts/` | Points d'entrée CLI pour les tâches batch | `services/`, `fetchers/` |
| `templates/` | Vues HTML rendues côté serveur par Jinja2 | Flask, Bootstrap 5.3 |
| `static/` | CSS et JavaScript chargés côté navigateur | Bootstrap Icons CDN |
| `data/` | Stockage persistant SQLite | Créé automatiquement par `repository.py` |

---

## 4. Documentation des Routes Backend

### 4.1 Vue d'ensemble

| Méthode | Route | Fonction | Description |
|---|---|---|---|
| `GET` | `/` | `index()` | Tableau de bord principal avec filtres |
| `GET` | `/detail/<cve_id>` | `detail()` | Fiche détaillée d'une vulnérabilité |
| `GET` | `/api/search` | `api_search()` | Recherche JSON (endpoint API) |
| `POST` | `/admin/analyze` | `run_analysis()` | Déclenche l'analyse LLM |

---

### 4.2 `GET /` — Tableau de bord

**Fonction** : `index()` dans `app.py`

Affiche la liste des vulnérabilités avec les statistiques globales. Supporte trois modes de filtrage exclusifs.

**Paramètres GET :**

| Paramètre | Type | Valeurs acceptées | Comportement |
|---|---|---|---|
| `severity` | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | Filtre par niveau de sévérité |
| `kev` | string | `1` | Affiche uniquement les vulnérabilités KEV |
| `q` | string | Texte libre (≥ 1 car.) | Recherche dans CVE ID, description, vendor, produit |

**Logique de priorité des filtres :**

```python
if search_query:
    vulnerabilities = search_vulnerabilities(search_query, limit=100)
elif kev_filter == "1":
    vulnerabilities = get_kev_vulnerabilities(limit=100)
elif severity_filter in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
    vulnerabilities = get_vulnerabilities_by_severity(severity_filter, limit=100)
else:
    vulnerabilities = get_recent_vulnerabilities(limit=100)
```

**Variables transmises au template :**

| Variable | Type | Description |
|---|---|---|
| `vulnerabilities` | `list[sqlite3.Row]` | Liste des CVE filtrées (max 100) |
| `stats` | `dict` | Compteurs globaux (total, critical, kev_count, high, analyzed) |
| `current_severity` | `str` | Filtre sévérité actif (pour l'affichage conditionnel) |
| `current_kev` | `str` | Filtre KEV actif (`"1"` ou `""`) |
| `search_query` | `str` | Terme recherché (pour pré-remplir le champ) |

---

### 4.3 `GET /detail/<cve_id>` — Fiche détaillée

**Fonction** : `detail()` dans `app.py`

Affiche toutes les informations d'une vulnérabilité, y compris l'analyse IA si disponible.

**Paramètre d'URL :**

| Paramètre | Type | Exemple | Description |
|---|---|---|---|
| `cve_id` | string (path) | `CVE-2024-12345` | Identifiant officiel de la CVE |

**Comportement :**
- Si `cve_id` n'existe pas en base → `abort(404)` → rendu de `404.html`
- Sinon → rendu de `detail.html` avec l'objet `sqlite3.Row` complet

---

### 4.4 `GET /api/search` — Recherche JSON

**Fonction** : `api_search()` dans `app.py`

Endpoint REST retournant les résultats de recherche au format JSON. Destiné à une utilisation programmatique ou à une intégration AJAX future.

**Paramètre GET :**

| Paramètre | Requis | Contrainte | Description |
|---|---|---|---|
| `q` | Oui | ≥ 2 caractères | Terme de recherche |

**Réponses :**

```json
// Succès (200)
{
  "query": "apache",
  "count": 3,
  "results": [
    {
      "cve_id": "CVE-2024-38475",
      "severity": "HIGH",
      "cvss_score": "7.5",
      "vendor": "Apache",
      "product": "HTTP Server",
      "published_date": "2024-07-01",
      "kev": false,
      "llm_analyzed": true
    }
  ]
}

// Erreur — paramètre manquant ou trop court (400)
{
  "error": "Le paramètre 'q' doit contenir au moins 2 caractères."
}
```

---

### 4.5 `POST /admin/analyze` — Déclenchement de l'analyse IA

**Fonction** : `run_analysis()` dans `app.py`

Déclenche l'analyse LLM des vulnérabilités non encore traitées (`llm_analyzed = 0`). Appelé depuis le bouton de l'interface web via une requête `fetch()` JavaScript.

**Paramètre de formulaire (POST body) :**

| Paramètre | Type | Défaut | Contrainte | Description |
|---|---|---|---|---|
| `limit` | integer | `10` | entre 1 et 50 | Nombre de CVE à analyser par lot |

**Réponses :**

```json
// Succès (200)
{
  "status": "success",
  "message": "8 vulnérabilité(s) analysée(s), 2 échec(s) sur 10 traitée(s).",
  "stats": {
    "total": 10,
    "analyzed": 8,
    "failed": 2
  }
}

// Erreur interne (500)
{
  "status": "error",
  "message": "Description de l'exception"
}
```

---

### 4.6 Gestion des erreurs

| Cas | Code HTTP | Comportement |
|---|---|---|
| CVE introuvable (`/detail/<id>`) | `404` | Rendu de `templates/404.html` |
| Paramètre `q` trop court (`/api/search`) | `400` | JSON `{"error": "..."}` |
| Exception dans l'analyse LLM | `500` | JSON `{"status": "error", "message": "..."}` |
| Quota Gemini dépassé | Transparent | Basculement automatique sur le simulateur |

### 4.7 Helpers Jinja2 enregistrés dans `app.py`

Ces fonctions sont disponibles directement dans tous les templates.

| Fonction | Paramètres | Retour | Usage |
|---|---|---|---|
| `safe_value(value, default)` | `value: any`, `default: str` | `str` | Remplace `None` ou chaîne vide par un texte par défaut |
| `severity_badge_class(severity)` | `severity: str` | `str` (classe CSS) | Retourne `badge-critical`, `badge-high`, etc. |
| `parse_references(refs_json)` | `refs_json: str` | `list[dict]` | Parse le JSON des références en liste de dicts `{"url": "..."}` |
| `format_score(score)` | `score: float|None` | `str` | Formate le CVSS en `"9.8"` ou `"N/A"` |

---

## 5. Logique Métier et Services

### 5.1 Collecte — `fetchers/`

#### `fetchers/nvd.py` — API NVD (NIST)

Interroge l'API officielle NVD v2.0 pour récupérer les dernières vulnérabilités publiées.

```python
def fetch_nvd_latest() -> list:
    params = {"resultsPerPage": FETCH_LIMIT}   # FETCH_LIMIT = 20 (config.py)
    response = requests.get(NVD_API_URL, params=params, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])
```

| Paramètre config | Valeur | Description |
|---|---|---|
| `NVD_API_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Endpoint NVD v2 |
| `FETCH_LIMIT` | `20` | Vulnérabilités récupérées par appel |
| `HTTP_TIMEOUT` | `30` secondes | Timeout des requêtes HTTP |

**Format retourné** : liste de dicts JSON bruts NVD (structure imbriquée `cve.metrics`, `cve.descriptions`, etc.)

---

#### `fetchers/cisa_kev.py` — Catalogue CISA KEV

Télécharge le catalogue complet des vulnérabilités activement exploitées publié par la CISA.

```python
def fetch_cisa_kev() -> list:
    response = requests.get(CISA_KEV_URL, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])
```

| Paramètre config | Valeur | Description |
|---|---|---|
| `CISA_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Feed JSON CISA |

**Format retourné** : liste de dicts avec les champs `cveID`, `vendorProject`, `product`, `shortDescription`, `dateAdded`.

---

### 5.2 Normalisation — `services/normalizer.py`

Ce module constitue l'**adaptateur** entre les formats hétérogènes des sources externes et le format interne unifié utilisé par toute l'application.

#### Format de sortie unifié

Toute vulnérabilité normalisée est un `dict` avec les clés suivantes :

| Clé | Type | Source NVD | Source CISA |
|---|---|---|---|
| `cve_id` | `str` | `cve.id` | `cveID` |
| `title` | `str` | `cve.id` (alias) | `cveID` (alias) |
| `published_date` | `str` (YYYY-MM-DD) | `cve.published[:10]` | `dateAdded` |
| `cvss_score` | `float\|None` | Extrait des métriques CVSS | `None` |
| `severity` | `str` | Extrait des métriques CVSS | `"Unknown"` |
| `kev` | `bool` | `False` | `True` |
| `source` | `str` | `"NVD"` | `"CISA-KEV"` |
| `vendor` | `str\|None` | `None` | `vendorProject` |
| `product` | `str\|None` | `None` | `product` |
| `description_raw` | `str` | Description anglaise | `shortDescription` |
| `references` | `str` (JSON) | URLs extraites | `"[]"` |

#### Priorité d'extraction CVSS

La fonction `_extract_cvss_from_nvd_metrics()` applique un ordre de priorité décroissant pour couvrir toutes les versions du standard :

```
CVSS v4.0  →  CVSS v3.1  →  CVSS v3.0  →  CVSS v2.0  →  (None, "Unknown")
```

---

### 5.3 Persistance — `services/repository.py`

Centralise **toutes** les interactions avec la base SQLite. Aucune requête SQL n'est écrite en dehors de ce fichier.

#### Schéma de la table `vulnerabilities`

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id           TEXT UNIQUE NOT NULL,   -- Identifiant officiel CVE
    title            TEXT,                   -- Titre (alias du cve_id)
    published_date   TEXT,                   -- Format YYYY-MM-DD
    cvss_score       REAL,                   -- Score base CVSS (0.0 – 10.0)
    severity         TEXT,                   -- CRITICAL / HIGH / MEDIUM / LOW / Unknown
    kev              INTEGER DEFAULT 0,      -- 1 si répertoriée CISA KEV, 0 sinon
    source           TEXT,                   -- "NVD", "CISA-KEV", ou "NVD,CISA-KEV"
    vendor           TEXT,                   -- Fournisseur (peut être NULL)
    product          TEXT,                   -- Produit affecté (peut être NULL)
    description_raw  TEXT,                   -- Description technique brute
    references_json  TEXT,                   -- JSON : liste d'URLs de référence
    llm_summary      TEXT,                   -- Résumé généré par Gemini
    llm_impact       TEXT,                   -- Impact généré par Gemini
    llm_mitigation   TEXT,                   -- Mitigation générée par Gemini
    llm_analyzed     INTEGER DEFAULT 0       -- 0 = non analysé, 1 = analysé
);
```

#### Catalogue des fonctions publiques

| Fonction | Retour | Description |
|---|---|---|
| `init_db()` | — | Crée la table et ajoute les colonnes manquantes (migration safe) |
| `upsert_vulnerability(vuln)` | — | Insert ou met à jour avec fusion intelligente des champs |
| `find_by_cve_id(cve_id)` | `sqlite3.Row\|None` | Récupère une vulnérabilité par son identifiant |
| `get_recent_vulnerabilities(limit)` | `list[Row]` | N plus récentes (tri par date desc) |
| `get_kev_vulnerabilities(limit)` | `list[Row]` | Vulnérabilités KEV uniquement |
| `get_vulnerabilities_by_severity(sev, limit)` | `list[Row]` | Filtre par sévérité |
| `search_vulnerabilities(query, limit)` | `list[Row]` | Recherche LIKE sur 4 champs |
| `get_unanalyzed_vulnerabilities(limit)` | `list[Row]` | `llm_analyzed = 0`, priorisé KEV + CVSS élevé |
| `get_analyzed_vulnerabilities(limit)` | `list[Row]` | `llm_analyzed = 1` |
| `save_llm_analysis(cve_id, summary, impact, mitigation)` | — | Sauvegarde les champs LLM et passe `llm_analyzed = 1` |
| `get_statistics()` | `dict` | Compteurs pour le tableau de bord |

#### Fusion intelligente (`merge_vulnerability`)

Quand une CVE arrive d'une deuxième source (ex : NVD puis CISA), les données sont **fusionnées** sans perte :

```python
merged = {
    "source": "NVD,CISA-KEV",       # Concaténation des sources
    "kev": True,                      # OR logique (KEV prioritaire)
    "cvss_score": existing_score,     # Conserve le score existant si présent
    "vendor": existing or incoming,   # Premier non-null
    "description_raw": existing or incoming,
    # ... llm_* toujours conservés
}
```

#### Priorité d'analyse (`get_unanalyzed_vulnerabilities`)

Les vulnérabilités sont retournées dans l'ordre suivant pour maximiser la valeur des analyses :

```sql
ORDER BY
    kev DESC,           -- 1. Exploitation active en priorité absolue
    cvss_score DESC,    -- 2. Score CVSS le plus élevé
    published_date DESC -- 3. Plus récentes
```

---

### 5.4 Analyse IA — `services/analyzer.py`

#### Vue d'ensemble du flux

```
get_unanalyzed_vulnerabilities()
    │
    ▼  (sqlite3.Row)
_to_dict()                          ← Correction bug sqlite3.Row
    │
    ▼  (dict Python)
build_prompt()
    │
    ▼  (str — prompt complet)
call_llm()
    │
    ├── GEMINI_API_KEY présente ──► Gemini API (gemini-2.5-flash-lite)
    │                                        │
    │   Exception / quota dépassé ◄──────────┘
    │         │
    └── Fallback ──► generate_fake_llm_analysis()
    │
    ▼  (str JSON ou dict)
parse_llm_output()  ──► extract_json()
    │
    ▼  (summary, impact, mitigation)
save_llm_analysis()  ──►  SQLite (llm_analyzed = 1)
```

#### Le prompt envoyé à Gemini

```
Tu es un analyste expert en cybersécurité défensive.
Ta mission : analyser des vulnérabilités CVE et produire des synthèses opérationnelles
en français pour aider une équipe de sécurité à prioriser et corriger les failles.

Règles strictes :
- Réponds UNIQUEMENT en JSON valide, sans texte avant ni après le bloc JSON.
- N'invente aucune information absente des données fournies.
- Si une donnée est manquante, utilise la valeur "non précisé".
- Adopte une perspective défensive et orientée remédiation.
- Rédige en français.

--- Données de la vulnérabilité ---
CVE ID              : CVE-2024-XXXX
Date de publication : 2024-07-01
Score CVSS          : 9.8
Sévérité            : CRITICAL
Exploitation active : Oui — répertoriée dans le catalogue CISA KEV
Vendor              : Apache
Produit             : HTTP Server
Description technique : [description brute NVD/CISA]
--- Fin des données ---

Produis UNIQUEMENT le JSON suivant :
{
  "summary": "Résumé technique en 2-3 phrases",
  "impact": "Impact potentiel sur les systèmes, données et continuité de service",
  "mitigation": "Actions de remédiation concrètes, priorisées et applicables immédiatement",
  "priority": "Haute | Moyenne | Basse"
}
```

#### Configuration du module

| Constante | Valeur | Description |
|---|---|---|
| `USE_REAL_LLM` | `bool(os.environ.get("GEMINI_API_KEY"))` | Auto-détecté selon la clé |
| `GEMINI_MODEL` | `"gemini-2.5-flash-lite"` | Modèle Gemini utilisé |
| `MAX_RETRIES` | `3` | Tentatives avant abandon |
| `RETRY_DELAY` | `3` secondes | Pause entre les tentatives |

#### Système de fallback

```
GEMINI_API_KEY absente
        OU
USE_REAL_LLM = False
        OU
Exception API (quota, réseau, format invalide)
        │
        ▼
generate_fake_llm_analysis(vuln)
  → Génère des textes cohérents basés sur severity, cvss_score, kev
  → Aucune erreur propagée vers l'utilisateur
  → Log WARNING dans la console
```

#### Parsing de la réponse Gemini

Gemini peut parfois entourer le JSON de blocs markdown (` ```json ... ``` `). La fonction `extract_json()` gère ce cas :

```python
def extract_json(text: str) -> dict:
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError("Aucun objet JSON trouvé dans la réponse Gemini")
    return json.loads(match.group())
```

---

### 5.5 Simulateur LLM — `services/llm_simulator.py`

Génère des analyses synthétiques cohérentes **sans appel réseau**, utilisé en mode développement ou en fallback.

| Champ généré | Logique |
|---|---|
| `summary` | `"Vulnérabilité {severity} affectant {vendor} {product}. {description[:150]}..."` |
| `impact` | Texte prédéfini par sévérité (CRITICAL / HIGH / MEDIUM / LOW) |
| `mitigation` | Message générique + urgence si KEV ou CVSS ≥ 9.0 |
| `priority` | `"Haute"` si KEV ou CVSS ≥ 7.0, `"Moyenne"` si CVSS ≥ 4.0, `"Basse"` sinon |

---

## 6. Interface Utilisateur

### 6.1 Templates Jinja2

L'interface repose sur un système de **template inheritance** Jinja2 avec un layout de base commun.

```
base.html                    ← Layout principal
    ├── index.html           ← hérite de base.html
    ├── detail.html          ← hérite de base.html
    └── 404.html             ← hérite de base.html (implicite)
```

#### `base.html` — Layout commun

Fournit la structure HTML partagée :

| Élément | Description |
|---|---|
| **Navbar** | Logo, liens (Toutes / KEV / Sévérité dropdown), barre de recherche `GET ?q=` |
| **Main** | Bloc `{% block content %}` remplacé par chaque page |
| **Footer** | Ligne descriptive du projet |
| **Assets CDN** | Bootstrap 5.3.3 CSS/JS, Bootstrap Icons 1.11.3 |
| **Assets locaux** | `static/style.css`, `static/app.js` |

La navbar détecte automatiquement le lien actif grâce aux variables de contexte Flask (`current_severity`, `current_kev`, `search_query`).

---

#### `index.html` — Tableau de bord

**Bloc 1 — Cartes statistiques :**

| Carte | Variable | Icône Bootstrap |
|---|---|---|
| Total CVE | `stats.total` | `bi-database` |
| Critiques | `stats.critical` | `bi-radioactive` |
| Exploitées (KEV) | `stats.kev_count` | `bi-exclamation-triangle` |
| Élevées | `stats.high` | `bi-shield-exclamation` |
| Analysées IA | `stats.analyzed` | `bi-robot` |

**Bloc 2 — Filtres actifs :** Badges affichant le filtre en cours avec un bouton de suppression individuel `×`.

**Bloc 3 — Tableau des vulnérabilités :**

| Colonne | Source | Triable | Description |
|---|---|---|---|
| CVE ID | `vuln['cve_id']` | Oui (alphanum.) | Lien vers `/detail/<cve_id>` |
| Sévérité | `vuln['severity']` | Oui (CRITICAL→LOW) | Badge coloré |
| Score | `vuln['cvss_score']` | Oui (numérique) | Couleur selon seuils CVSS |
| Vendor / Produit | `vuln['vendor']` + `vuln['product']` | Non | Deux lignes superposées |
| Date | `vuln['published_date']` | Oui (alpha) | Format YYYY-MM-DD |
| KEV | `vuln['kev']` | Non | Badge orange ou `—` |
| IA | `vuln['llm_analyzed']` | Non | Badge vert ✓ ou gris ⌛ |
| Actions | — | Non | Bouton `→` vers le détail |

**Bloc 4 — Déclencheur d'analyse IA :**

```html
<select id="analyzeLimit">  <!-- 5 / 10 / 20 / 50 vulnérabilités -->
<button onclick="triggerAnalysis()">Lancer l'analyse IA</button>
<span id="analyzeStatus"></span>
```

---

#### `detail.html` — Fiche CVE

**Colonne principale (8/12) :**
- **Description brute** : texte NVD/CISA complet
- **Analyse IA** (si `vuln['llm_analyzed'] == 1`) : carte avec fond semi-transparent bleu et trois sections (Résumé / Impact / Mitigation)
- **En attente** (si non analysé) : message d'information avec icône sablier

**Colonne latérale (4/12) :**
- **Tableau de métadonnées** : tous les champs de la CVE
- **Références** : liens cliquables vers les sources (NVD, CVSS, patches)
- **Navigation rapide** : retour tableau, filtre par sévérité, filtre KEV

---

#### `404.html` — Erreur personnalisée

Page centrée avec icône `bi-shield-x` et bouton de retour au tableau de bord.

---

### 6.2 Thème CSS — `static/style.css`

Le thème est basé sur une palette de couleurs **inspirée de GitHub Dark**, déclinée pour la cybersécurité.

#### Variables CSS

```css
:root {
    --vg-bg-primary:   #0d1117;   /* Fond de page */
    --vg-bg-secondary: #161b22;   /* Navbar, en-têtes cartes */
    --vg-bg-card:      #1c2333;   /* Cartes, tableau */
    --vg-bg-hover:     #21283b;   /* Hover sur lignes/cartes */
    --vg-border:       #30363d;   /* Toutes les bordures */
    --vg-text:         #e6edf3;   /* Texte principal */
    --vg-text-muted:   #8b949e;   /* Texte secondaire */
    --vg-accent:       #58a6ff;   /* Liens, icônes actives */
    --vg-critical:     #ff4757;   /* CRITICAL */
    --vg-high:         #ff7f50;   /* HIGH */
    --vg-medium:       #ffa502;   /* MEDIUM */
    --vg-low:          #2ed573;   /* LOW / Succès */
    --vg-kev:          #f0ad4e;   /* Badge KEV */
    --vg-ai-border:    #388bfd40; /* Bordure carte IA */
}
```

#### Conventions de nommage CSS

Toutes les classes personnalisées sont préfixées `.vg-` pour éviter les conflits avec Bootstrap.

| Préfixe | Composant |
|---|---|
| `.vg-navbar` | Barre de navigation |
| `.vg-stat-card` | Cartes de statistiques |
| `.vg-table`, `.vg-row` | Tableau des vulnérabilités |
| `.vg-card`, `.vg-card-ai` | Cartes de contenu (carte IA = style distinct) |
| `.badge-critical/high/medium/low` | Badges de sévérité |
| `.score-critical/high/medium/low` | Couleur du score CVSS |
| `.vg-score-big` | Score CVSS grand format (page détail) |

---

### 6.3 JavaScript — `static/app.js`

#### Tri des colonnes du tableau

```javascript
// Algorithme de tri côté client (aucun rechargement de page)
headers.forEach(header => header.addEventListener("click", () => {
    sortTable(header.dataset.sort, currentSort.ascending);
}));
```

Ordre des sévérités défini explicitement pour un tri logique (non alphabétique) :
```javascript
const sev = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, UNKNOWN: 5 };
```

#### Lignes cliquables

Toute ligne du tableau est cliquable et redirige vers `/detail/<cve_id>`, sauf si le clic cible un lien ou un bouton enfant.

```javascript
row.addEventListener("click", (e) => {
    if (e.target.closest("a") || e.target.closest("button")) return;
    window.location.href = `/detail/${row.dataset.cve}`;
});
```

#### Raccourcis clavier

| Touche | Action |
|---|---|
| `/` | Positionne le focus sur la barre de recherche |
| `Escape` | Retire le focus de la barre de recherche |

#### Déclencheur d'analyse IA (inline dans `index.html`)

```javascript
async function triggerAnalysis() {
    // 1. Désactive le bouton + affiche le spinner
    // 2. POST /admin/analyze avec le paramètre limit
    // 3. Affiche le résultat (vert = succès, rouge = erreur)
    // 4. Recharge la page après 1.5s si succès (pour MAJ des stats)
}
```

---

## 7. Procédures Techniques

### 7.1 Installation

```bash
# 1. Cloner le projet
git clone <url-du-repo>
cd vigilant-guardian

# 2. Créer un environnement virtuel
python -m venv venv

# 3. Activer l'environnement
# Windows :
venv\Scripts\activate
# macOS / Linux :
source venv/bin/activate

# 4. Installer les dépendances
pip install -r requirements.txt
```

**Contenu de `requirements.txt` :**

| Package | Rôle |
|---|---|
| `Flask` | Framework web Python |
| `requests` | Appels HTTP vers NVD et CISA |
| `python-dotenv` | Chargement du fichier `.env` |
| `pytest` | Framework de test |
| `google-genai` | SDK officiel Google Gemini (nouveau SDK ≥ 1.0) |

---

### 7.2 Configuration du fichier `.env`

Créer un fichier `.env` à la racine du projet :

```env
GEMINI_API_KEY=AIzaSy...votre_clé_Google_AI_Studio
```

> **Note** : Ce fichier ne doit **jamais** être versionné. Il est présent dans `.gitignore`.
>
> Obtenir une clé gratuite : [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

---

### 7.3 Initialisation de la base de données

La base est initialisée **automatiquement** au démarrage de l'application Flask. Elle peut aussi être initialisée manuellement :

```python
# Via Python
from services.repository import init_db
init_db()
```

La fonction `init_db()` est **idempotente** : elle crée la table si elle n'existe pas, et ajoute les colonnes manquantes si la base existait déjà (migration non destructive).

---

### 7.4 Mise à jour des données (collecte)

```bash
# Depuis la racine du projet
python scripts/update_data.py
```

Ce script :
1. Appelle `fetch_nvd_latest()` → 20 CVE récentes
2. Appelle `fetch_cisa_kev()` → catalogue complet KEV
3. Normalise chaque entrée via `normalizer.py`
4. Appelle `upsert_vulnerability()` pour chaque CVE (insert ou fusion)
5. Affiche les statistiques finales

**Sortie attendue :**
```
Récupération NVD...
Récupération CISA KEV...

Mise à jour terminée.
Entrées NVD traitées : 20
Entrées CISA KEV traitées : 1247
Nombre total de vulnérabilités uniques : 1250
...
```

---

### 7.5 Analyse IA batch (ligne de commande)

```bash
# Analyser 10 CVE (défaut)
python scripts/analyze_new.py

# Analyser 25 CVE
python scripts/analyze_new.py --limit 25
```

**Arguments :**

| Argument | Type | Défaut | Description |
|---|---|---|---|
| `--limit` | int | `10` | Nombre maximum de CVE à analyser |

**Comportement :**
- Récupère les CVE avec `llm_analyzed = 0` (KEV et CVSS élevé en priorité)
- Appelle Gemini ou le simulateur selon la disponibilité de `GEMINI_API_KEY`
- Jusqu'à 3 tentatives par CVE en cas d'échec temporaire
- Pause de 3 secondes entre les tentatives

---

### 7.6 Lancement de l'application web

```bash
# Mode développement (rechargement automatique)
python app.py

# Ou via Flask CLI
flask --app app run --debug --port 5100
```

L'application est accessible sur : **http://localhost:5100**

**Analyse IA depuis l'interface :**
1. Ouvrir le tableau de bord
2. Sélectionner le nombre de CVE à analyser (5 / 10 / 20 / 50)
3. Cliquer sur **"Lancer l'analyse IA"**
4. Le bouton affiche un spinner pendant le traitement
5. Le résultat s'affiche en vert (succès) ou rouge (erreur)
6. La page se recharge automatiquement après 1,5 s pour mettre à jour les statistiques

---

## 8. Variables d'Environnement

| Variable | Fichier | Requis | Description |
|---|---|---|---|
| `GEMINI_API_KEY` | `.env` | **Recommandé** | Clé API Google AI Studio. Si absente, le simulateur prend le relais automatiquement. |

**Variables de configuration internes** (dans `config.py`, non sensibles) :

| Variable | Valeur | Description |
|---|---|---|
| `SECRET_KEY` | `"vigilant-guardian-dev-key-2024"` | Clé secrète Flask (à changer en production) |
| `DEBUG` | `True` | Mode debug Flask |
| `HOST` | `"0.0.0.0"` | Interface d'écoute |
| `PORT` | `5100` | Port d'écoute |
| `FETCH_LIMIT` | `20` | Nombre de CVE NVD par requête |
| `HTTP_TIMEOUT` | `30` | Timeout HTTP en secondes |

---

*Document généré le 21 avril 2026 — Vigilant Guardian v1.0*
