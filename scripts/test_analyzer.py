from services.repository import init_db
from services.analyzer import analyze_vulnerabilities


def main():

    init_db()

    analyze_vulnerabilities(limit=3)


if __name__ == "__main__":
    main()