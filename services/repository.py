"""
Repository de la base de données.

Ce module centralise toutes les interactions avec SQLite.

Responsabilités :
- créer la base et les tables
- faire évoluer le schéma si nécessaire
- insérer / mettre à jour les vulnérabilités
- fusionner les données venant de plusieurs sources
- lire les vulnérabilités selon différents critères
- préparer l'intégration du module LLM

Fonctions ajoutées par la Personne 3 :
- search_vulnerabilities(query, limit) — recherche textuelle
- get_statistics() — compteurs pour le tableau de bord
"""

import sqlite3
from config import DB_PATH, DATA_DIR


# ---------------------------------------------------
# Connexion à la base
# ---------------------------------------------------

def get_connection():
    """
    Ouvre une connexion vers la base SQLite.
    Le dossier data/ est créé automatiquement si besoin.
    """
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------
# Utilitaires schéma
# ---------------------------------------------------

def _get_existing_columns(conn, table_name: str) -> set:
    """
    Retourne l'ensemble des colonnes existantes pour une table.
    """
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    rows = cursor.fetchall()
    return {row["name"] for row in rows}


def _add_column_if_missing(conn, table_name: str, column_name: str, column_definition: str):
    """
    Ajoute une colonne à une table si elle n'existe pas encore.
    """
    existing_columns = _get_existing_columns(conn, table_name)
    if column_name not in existing_columns:
        cursor = conn.cursor()
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )


# ---------------------------------------------------
# Initialisation / migration de la base
# ---------------------------------------------------

def init_db():
    """
    Initialise la base de données.
    - crée la table vulnerabilities si nécessaire
    - ajoute les colonnes manquantes si la base existait déjà
    """
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            title TEXT,
            published_date TEXT,
            cvss_score REAL,
            severity TEXT,
            kev INTEGER DEFAULT 0,
            source TEXT,
            vendor TEXT,
            product TEXT,
            description_raw TEXT,
            references_json TEXT,
            llm_summary TEXT,
            llm_impact TEXT,
            llm_mitigation TEXT,
            llm_analyzed INTEGER DEFAULT 0
        )
    """)

    _add_column_if_missing(conn, "vulnerabilities", "llm_summary", "TEXT")
    _add_column_if_missing(conn, "vulnerabilities", "llm_impact", "TEXT")
    _add_column_if_missing(conn, "vulnerabilities", "llm_mitigation", "TEXT")
    _add_column_if_missing(conn, "vulnerabilities", "llm_analyzed", "INTEGER DEFAULT 0")

    conn.commit()
    conn.close()


# ---------------------------------------------------
# Lecture simple
# ---------------------------------------------------

def find_by_cve_id(cve_id: str):
    """
    Recherche une vulnérabilité par son identifiant CVE.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE cve_id = ?
    """, (cve_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_analysis_by_cve_id(cve_id: str):
    """
    Retourne uniquement les champs liés à l'analyse LLM
    pour une vulnérabilité donnée.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT
            cve_id,
            llm_summary,
            llm_impact,
            llm_mitigation,
            llm_analyzed
        FROM vulnerabilities
        WHERE cve_id = ?
    """, (cve_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_all_vulnerabilities():
    """
    Retourne toutes les vulnérabilités stockées,
    triées par date décroissante.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        ORDER BY published_date DESC, cve_id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_recent_vulnerabilities(limit: int = 20):
    """
    Retourne les vulnérabilités les plus récentes.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        ORDER BY published_date DESC, cve_id ASC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_kev_vulnerabilities(limit: int | None = None):
    """
    Retourne les vulnérabilités KEV.
    """
    conn = get_connection()
    cursor = conn.cursor()
    if limit is None:
        cursor.execute("""
            SELECT *
            FROM vulnerabilities
            WHERE kev = 1
            ORDER BY published_date DESC, cve_id ASC
        """)
    else:
        cursor.execute("""
            SELECT *
            FROM vulnerabilities
            WHERE kev = 1
            ORDER BY published_date DESC, cve_id ASC
            LIMIT ?
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_vulnerabilities_by_severity(severity: str, limit: int | None = None):
    """
    Retourne les vulnérabilités pour un niveau de sévérité donné.
    """
    conn = get_connection()
    cursor = conn.cursor()
    if limit is None:
        cursor.execute("""
            SELECT *
            FROM vulnerabilities
            WHERE severity = ?
            ORDER BY published_date DESC, cve_id ASC
        """, (severity,))
    else:
        cursor.execute("""
            SELECT *
            FROM vulnerabilities
            WHERE severity = ?
            ORDER BY published_date DESC, cve_id ASC
            LIMIT ?
        """, (severity, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def count_vulnerabilities():
    """
    Retourne le nombre total de vulnérabilités stockées.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM vulnerabilities
    """)
    row = cursor.fetchone()
    conn.close()
    return row["total"]


def count_kev_vulnerabilities():
    """
    Retourne le nombre total de vulnérabilités KEV.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM vulnerabilities
        WHERE kev = 1
    """)
    row = cursor.fetchone()
    conn.close()
    return row["total"]


# ---------------------------------------------------
# Lecture pour module LLM
# ---------------------------------------------------

def get_unanalyzed_vulnerabilities(limit: int = 20):
    """
    Retourne les vulnérabilités qui n'ont pas encore été analysées par le LLM.

    Priorité :
    - vulnérabilités KEV d'abord
    - puis score CVSS le plus élevé
    - puis plus récentes
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE llm_analyzed = 0
        ORDER BY
            kev DESC,
            cvss_score DESC,
            published_date DESC,
            cve_id ASC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_analyzed_vulnerabilities(limit: int = 20):
    """
    Retourne les vulnérabilités déjà analysées par le LLM.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE llm_analyzed = 1
        ORDER BY published_date DESC, cve_id ASC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ---------------------------------------------------
# Insertion interne
# ---------------------------------------------------

def _insert_vulnerability(conn, vuln: dict):
    """
    Insère une nouvelle vulnérabilité.
    Cette fonction suppose que la CVE n'existe pas encore.
    """
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (
            cve_id,
            title,
            published_date,
            cvss_score,
            severity,
            kev,
            source,
            vendor,
            product,
            description_raw,
            references_json,
            llm_summary,
            llm_impact,
            llm_mitigation,
            llm_analyzed
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        vuln["cve_id"],
        vuln["title"],
        vuln["published_date"],
        vuln["cvss_score"],
        vuln["severity"],
        int(vuln["kev"]),
        vuln["source"],
        vuln["vendor"],
        vuln["product"],
        vuln["description_raw"],
        vuln["references"],
        None,
        None,
        None,
        0
    ))


# ---------------------------------------------------
# Fusion intelligente
# ---------------------------------------------------

def merge_vulnerability(existing, incoming: dict) -> dict:
    """
    Fusionne une vulnérabilité existante avec une nouvelle version.
    """
    existing_source = existing["source"] or ""
    incoming_source = incoming["source"] or ""

    if existing_source and incoming_source and incoming_source not in existing_source:
        merged_source = f"{existing_source},{incoming_source}"
    else:
        merged_source = existing_source or incoming_source

    merged = {
        "cve_id": existing["cve_id"],
        "title": existing["title"] or incoming["title"],
        "published_date": existing["published_date"] or incoming["published_date"],
        "cvss_score": (
            existing["cvss_score"]
            if existing["cvss_score"] is not None
            else incoming["cvss_score"]
        ),
        "severity": (
            existing["severity"]
            if existing["severity"] not in (None, "", "Unknown")
            else incoming["severity"]
        ),
        "kev": bool(existing["kev"]) or bool(incoming["kev"]),
        "source": merged_source,
        "vendor": existing["vendor"] or incoming["vendor"],
        "product": existing["product"] or incoming["product"],
        "description_raw": (
            existing["description_raw"]
            if existing["description_raw"] not in (None, "", "Non précisé")
            else incoming["description_raw"]
        ),
        "references": (
            existing["references_json"]
            if existing["references_json"] not in (None, "", "[]")
            else incoming["references"]
        ),
        "llm_summary": existing["llm_summary"],
        "llm_impact": existing["llm_impact"],
        "llm_mitigation": existing["llm_mitigation"],
        "llm_analyzed": existing["llm_analyzed"]
    }
    return merged


def _update_vulnerability(conn, vuln: dict):
    """
    Met à jour une vulnérabilité existante.
    """
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE vulnerabilities
        SET
            title = ?,
            published_date = ?,
            cvss_score = ?,
            severity = ?,
            kev = ?,
            source = ?,
            vendor = ?,
            product = ?,
            description_raw = ?,
            references_json = ?,
            llm_summary = ?,
            llm_impact = ?,
            llm_mitigation = ?,
            llm_analyzed = ?
        WHERE cve_id = ?
    """, (
        vuln["title"],
        vuln["published_date"],
        vuln["cvss_score"],
        vuln["severity"],
        int(vuln["kev"]),
        vuln["source"],
        vuln["vendor"],
        vuln["product"],
        vuln["description_raw"],
        vuln["references"],
        vuln["llm_summary"],
        vuln["llm_impact"],
        vuln["llm_mitigation"],
        int(vuln["llm_analyzed"]),
        vuln["cve_id"]
    ))


# ---------------------------------------------------
# Fonction publique principale
# ---------------------------------------------------

def upsert_vulnerability(vuln: dict):
    """
    Insère ou met à jour une vulnérabilité.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT *
            FROM vulnerabilities
            WHERE cve_id = ?
        """, (vuln["cve_id"],))
        existing = cursor.fetchone()

        if existing is None:
            _insert_vulnerability(conn, vuln)
        else:
            merged = merge_vulnerability(existing, vuln)
            _update_vulnerability(conn, merged)

        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------
# Mise à jour LLM
# ---------------------------------------------------

def save_llm_analysis(cve_id: str, summary: str, impact: str, mitigation: str):
    """
    Sauvegarde l'analyse LLM pour une vulnérabilité donnée.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE vulnerabilities
        SET
            llm_summary = ?,
            llm_impact = ?,
            llm_mitigation = ?,
            llm_analyzed = 1
        WHERE cve_id = ?
    """, (summary, impact, mitigation, cve_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------
# Fonctions ajoutées par Personne 3 (interface web)
# ---------------------------------------------------

def search_vulnerabilities(query: str, limit: int = 50):
    """
    Recherche par mot-clé dans CVE ID, description, vendor ou product.
    Utilisée par la route /api/search et le filtre de recherche.
    """
    conn = get_connection()
    cursor = conn.cursor()
    search_term = f"%{query}%"
    cursor.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE cve_id LIKE ?
           OR description_raw LIKE ?
           OR vendor LIKE ?
           OR product LIKE ?
        ORDER BY published_date DESC, cve_id ASC
        LIMIT ?
    """, (search_term, search_term, search_term, search_term, limit))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_statistics() -> dict:
    """
    Retourne des statistiques globales pour le tableau de bord.
    Utilisée par la page d'accueil.
    """
    conn = get_connection()
    cursor = conn.cursor()
    stats = {}

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities")
    stats["total"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE kev = 1")
    stats["kev_count"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE llm_analyzed = 1")
    stats["analyzed"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE UPPER(severity) = 'CRITICAL'")
    stats["critical"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE UPPER(severity) = 'HIGH'")
    stats["high"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE UPPER(severity) = 'MEDIUM'")
    stats["medium"] = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM vulnerabilities WHERE UPPER(severity) = 'LOW'")
    stats["low"] = cursor.fetchone()["total"]

    conn.close()
    return stats
