"""
Script batch pour analyser les nouvelles vulnérabilités (Personne 2).

Usage:
    python scripts/analyze_new.py --limit 5
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.repository import init_db
from services.analyzer import analyze_vulnerabilities


def main():
    parser = argparse.ArgumentParser(
        description="Analyse des vulnérabilités non traitées"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Nombre maximum de vulnérabilités à analyser",
    )
    args = parser.parse_args()

    init_db()
    print(f"Lancement analyse de {args.limit} vulnérabilités...\n")
    analyze_vulnerabilities(limit=args.limit)
    print("\nAnalyse terminée.")


if __name__ == "__main__":
    main()
