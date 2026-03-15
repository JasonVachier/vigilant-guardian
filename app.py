from flask import Flask, jsonify
from services.analyzer import analyze_vulnerabilities

app = Flask(__name__)

@app.route("/admin/analyze", methods=["POST"])
def run_analysis():

    try:
        analyze_vulnerabilities(limit=10)

        return jsonify({
            "status": "success",
            "message": "Analyse des vulnérabilités lancée"
        })

    except Exception as e:

        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500