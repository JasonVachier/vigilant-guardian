"""
app.py — Application Flask principale (Personne 3)
Interface web pour consulter les vulnérabilités CVE collectées et analysées.

Routes :
  /                  → Page d'accueil avec tableau filtrable
  /detail/<cve_id>   → Fiche détaillée d'une vulnérabilité
  /api/search        → Endpoint de recherche JSON

Règles respectées :
  - Utilisation exclusive de repository.py comme couche d'accès aux données
  - Pas de SQL dispersé dans ce fichier
  - Gestion des champs null/Unknown pour severity, cvss_score, vendor, product, llm_*
  - cve_id comme identifiant unique pour les routes
"""

from flask import Flask, render_template, request, jsonify, abort
import json

from dotenv import load_dotenv
load_dotenv()

from services.repository import (
    get_recent_vulnerabilities,
    get_kev_vulnerabilities,
    get_vulnerabilities_by_severity,
    find_by_cve_id,
    search_vulnerabilities,
    get_statistics,
    init_db,
)
from config import SECRET_KEY, DEBUG, HOST, PORT

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# Initialisation de la base au démarrage (couvre flask run et gunicorn)
with app.app_context():
    init_db()


# ── Helpers Jinja2 ─────────────────────────────────────────────

def safe_value(value, default="Non disponible"):
    """Retourne une valeur sûre pour l'affichage, gérant None et chaînes vides."""
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return default
    return value


def severity_badge_class(severity):
    """Retourne la classe CSS pour un badge de sévérité."""
    mapping = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
    }
    sev = (severity or "Unknown").upper()
    return mapping.get(sev, "badge-unknown")


def parse_references(refs_json):
    """Parse le champ references_json de manière sécurisée."""
    if not refs_json:
        return []
    try:
        refs = json.loads(refs_json)
        if isinstance(refs, list):
            # Accepte les deux formats : liste de dicts OU liste de strings
            result = []
            for r in refs:
                if isinstance(r, dict):
                    result.append(r)
                elif isinstance(r, str):
                    result.append({"url": r})
            return result
        return []
    except (json.JSONDecodeError, TypeError):
        return []


def format_score(score):
    """Formate le score CVSS pour l'affichage."""
    if score is None:
        return "N/A"
    try:
        return f"{float(score):.1f}"
    except (ValueError, TypeError):
        return "N/A"


# Enregistrement des filtres Jinja2
app.jinja_env.globals.update(
    safe_value=safe_value,
    severity_badge_class=severity_badge_class,
    parse_references=parse_references,
    format_score=format_score,
)


# ── Routes ─────────────────────────────────────────────────────

@app.route("/")
def index():
    """
    Page d'accueil — tableau des vulnérabilités avec filtres.
    Paramètres GET :
      severity → filtre par sévérité (CRITICAL, HIGH, MEDIUM, LOW)
      kev      → filtre KEV uniquement (1)
      q        → recherche textuelle
    """
    severity_filter = request.args.get("severity", "").strip().upper()
    kev_filter = request.args.get("kev", "").strip()
    search_query = request.args.get("q", "").strip()

    if search_query:
        vulnerabilities = search_vulnerabilities(search_query, limit=100)
    elif kev_filter == "1":
        vulnerabilities = get_kev_vulnerabilities(limit=100)
    elif severity_filter in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        vulnerabilities = get_vulnerabilities_by_severity(severity_filter, limit=100)
    else:
        vulnerabilities = get_recent_vulnerabilities(limit=100)

    stats = get_statistics()

    return render_template(
        "index.html",
        vulnerabilities=vulnerabilities,
        stats=stats,
        current_severity=severity_filter,
        current_kev=kev_filter,
        search_query=search_query,
    )


@app.route("/detail/<cve_id>")
def detail(cve_id):
    """Fiche détaillée d'une vulnérabilité identifiée par son CVE ID."""
    vuln = find_by_cve_id(cve_id)
    if vuln is None:
        abort(404)
    return render_template("detail.html", vuln=vuln)


@app.route("/api/search")
def api_search():
    """
    Endpoint API JSON pour la recherche de vulnérabilités.
    Paramètre GET : q (mot-clé de recherche)
    Retourne : liste JSON de vulnérabilités correspondantes
    """
    query = request.args.get("q", "").strip()
    if not query or len(query) < 2:
        return jsonify({"error": "Le paramètre 'q' doit contenir au moins 2 caractères."}), 400

    results = search_vulnerabilities(query, limit=20)

    formatted = []
    for v in results:
        formatted.append({
            "cve_id": v["cve_id"],
            "severity": safe_value(v["severity"], "Unknown"),
            "cvss_score": format_score(v["cvss_score"]),
            "vendor": safe_value(v["vendor"], "Unknown"),
            "product": safe_value(v["product"], "Unknown"),
            "published_date": safe_value(v["published_date"], "Unknown"),
            "kev": bool(v["kev"]),
            "llm_analyzed": bool(v["llm_analyzed"]),
        })

    return jsonify({"query": query, "count": len(formatted), "results": formatted})


@app.errorhandler(404)
def not_found(e):
    """Page d'erreur 404."""
    return render_template("404.html"), 404


# ── Route Personne 2 — Déclenchement analyse LLM ──────────────

@app.route("/admin/analyze", methods=["POST"])
def run_analysis():
    """
    Déclenche l'analyse LLM des vulnérabilités non encore traitées.
    Retourne les statistiques d'exécution (total, analyzed, failed).
    """
    try:
        limit = int(request.form.get("limit", 10))
        limit = max(1, min(limit, 50))  # borne entre 1 et 50
    except (ValueError, TypeError):
        limit = 10

    try:
        from services.analyzer import analyze_vulnerabilities
        stats = analyze_vulnerabilities(limit=limit)
        return jsonify({
            "status": "success",
            "message": (
                f"{stats['analyzed']} vulnérabilité(s) analysée(s), "
                f"{stats['failed']} échec(s) sur {stats['total']} traitée(s)."
            ),
            "stats": stats,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


# ── Point d'entrée ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=DEBUG, host=HOST, port=PORT)
