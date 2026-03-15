"""
seed_data.py — Insère des données de démonstration réalistes dans la base.
Simule le travail combiné de la Personne 1 (collecte) et Personne 2 (analyse LLM).
Compatible avec le schéma exact de la Personne 1 (repository.py).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.repository import init_db, upsert_vulnerability, save_llm_analysis

# Données réalistes basées sur les CVE critiques de 2025
SEED_VULNS = [
    {
        "cve_id": "CVE-2025-3400",
        "title": "CVE-2025-3400",
        "published_date": "2025-04-12",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS GlobalProtect",
        "description_raw": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-3400"},{"url":"https://security.paloaltonetworks.com/CVE-2025-3400"}]',
    },
    {
        "cve_id": "CVE-2025-21887",
        "title": "CVE-2025-21887",
        "published_date": "2025-01-12",
        "cvss_score": 9.1,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Ivanti",
        "product": "Connect Secure / Policy Secure",
        "description_raw": "A command injection vulnerability in web components of Ivanti Connect Secure and Ivanti Policy Secure allows an authenticated administrator to send specially crafted requests and execute arbitrary commands on the appliance.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-21887"}]',
    },
    {
        "cve_id": "CVE-2025-1709",
        "title": "CVE-2025-1709",
        "published_date": "2025-02-19",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "ConnectWise",
        "product": "ScreenConnect",
        "description_raw": "ConnectWise ScreenConnect 23.9.7 and prior are affected by an Authentication Bypass Using an Alternate Path or Channel vulnerability, which may allow an attacker direct access to confidential information or critical systems.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-1709"}]',
    },
    {
        "cve_id": "CVE-2025-4577",
        "title": "CVE-2025-4577",
        "published_date": "2025-06-09",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "PHP Group",
        "product": "PHP (CGI)",
        "description_raw": "In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, if the system is set up to use certain code pages, Windows may use Best-Fit behavior to replace characters in the command line given to Win32 API functions. PHP CGI module may misinterpret those characters as PHP options, which may allow a malicious user to pass options to the PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the server, etc.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-4577"}]',
    },
    {
        "cve_id": "CVE-2025-6387",
        "title": "CVE-2025-6387",
        "published_date": "2025-07-01",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "kev": False,
        "source": "NVD",
        "vendor": "OpenSSH",
        "product": "OpenSSH (sshd)",
        "description_raw": "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds (120 by default), then sshd's SIGALRM handler is called asynchronously. This signal handler calls various functions that are not async-signal-safe. A remote unauthenticated attacker may be able to trigger this condition to achieve remote code execution as root.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-6387"},{"url":"https://www.qualys.com/2025/07/01/cve-2025-6387/regresshion.txt"}]',
    },
    {
        "cve_id": "CVE-2025-38077",
        "title": "CVE-2025-38077",
        "published_date": "2025-07-09",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": False,
        "source": "NVD",
        "vendor": "Microsoft",
        "product": "Windows Remote Desktop Licensing Service",
        "description_raw": "Windows Remote Desktop Licensing Service Remote Code Execution Vulnerability. A heap-based buffer overflow in the Windows Remote Desktop Licensing Service allows a remote unauthenticated attacker to execute arbitrary code.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-38077"}]',
    },
    {
        "cve_id": "CVE-2025-23113",
        "title": "CVE-2025-23113",
        "published_date": "2025-02-15",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Fortinet",
        "product": "FortiOS / FortiProxy / FortiPAM / FortiSwitchManager",
        "description_raw": "A use of externally-controlled format string in Fortinet FortiOS, FortiProxy, FortiPAM and FortiSwitchManager allows attacker to execute unauthorized code or commands via specially crafted packets.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-23113"}]',
    },
    {
        "cve_id": "CVE-2025-47575",
        "title": "CVE-2025-47575",
        "published_date": "2025-10-23",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Fortinet",
        "product": "FortiManager",
        "description_raw": "A missing authentication for critical function vulnerability in FortiManager fgfmd daemon may allow a remote unauthenticated attacker to execute arbitrary code or commands via specially crafted requests.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-47575"}]',
    },
    {
        "cve_id": "CVE-2025-0012",
        "title": "CVE-2025-0012",
        "published_date": "2025-11-18",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS Management Interface",
        "description_raw": "An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated attacker with network access to the management web interface to gain PAN-OS administrator privileges.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-0012"}]',
    },
    {
        "cve_id": "CVE-2025-21762",
        "title": "CVE-2025-21762",
        "published_date": "2025-02-09",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Fortinet",
        "product": "FortiOS SSL VPN",
        "description_raw": "A out-of-bounds write in Fortinet FortiOS allows attacker to execute unauthorized code or commands via specifically crafted HTTP requests.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-21762"}]',
    },
    {
        "cve_id": "CVE-2025-28995",
        "title": "CVE-2025-28995",
        "published_date": "2025-06-06",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "SolarWinds",
        "product": "Serv-U",
        "description_raw": "SolarWinds Serv-U was susceptible to a directory transversal vulnerability that would allow access to read sensitive files on the host machine.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-28995"}]',
    },
    {
        "cve_id": "CVE-2025-5910",
        "title": "CVE-2025-5910",
        "published_date": "2025-07-10",
        "cvss_score": 9.3,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Palo Alto Networks",
        "product": "Expedition",
        "description_raw": "Missing authentication for a critical function in Palo Alto Networks Expedition can lead to an Expedition admin account takeover for attackers with network access to Expedition.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-5910"}]',
    },
    {
        "cve_id": "CVE-2025-36401",
        "title": "CVE-2025-36401",
        "published_date": "2025-07-01",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": False,
        "source": "NVD",
        "vendor": "GeoServer",
        "product": "GeoServer",
        "description_raw": "GeoServer is an open source server that allows users to share and edit geospatial data. Prior to versions 2.23.6 and 2.24.4, GeoServer evaluates property name/attribute name expressions as XPath expressions in a way that allows arbitrary code execution.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-36401"}]',
    },
    {
        "cve_id": "CVE-2025-50623",
        "title": "CVE-2025-50623",
        "published_date": "2025-11-27",
        "cvss_score": None,
        "severity": "Unknown",
        "kev": True,
        "source": "CISA-KEV",
        "vendor": "Cleo",
        "product": "Harmony / VLTrader / LexiCom",
        "description_raw": "In Cleo Harmony before 5.8.0.21, VLTrader before 5.8.0.21, and LexiCom before 5.8.0.21, there is an unrestricted file upload and download vulnerability that could lead to remote code execution.",
        "references": '[]',
    },
    {
        "cve_id": "CVE-2025-11680",
        "title": "CVE-2025-11680",
        "published_date": "2025-11-26",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": False,
        "source": "NVD",
        "vendor": "ProjectSend",
        "product": "ProjectSend",
        "description_raw": "ProjectSend versions prior to r1720 are affected by an improper authentication vulnerability. Remote, unauthenticated attackers can exploit this flaw by sending crafted HTTP requests to options.php, enabling unauthorized modification of the application configuration.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-11680"}]',
    },
    {
        "cve_id": "CVE-2025-40711",
        "title": "CVE-2025-40711",
        "published_date": "2025-09-07",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Veeam",
        "product": "Veeam Backup & Replication",
        "description_raw": "A deserialization of untrusted data vulnerability with a CVSS score of 9.8 in Veeam Backup & Replication allows unauthenticated remote code execution (RCE).",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-40711"}]',
    },
    {
        "cve_id": "CVE-2025-9474",
        "title": "CVE-2025-9474",
        "published_date": "2025-11-18",
        "cvss_score": 7.2,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "description_raw": "A privilege escalation vulnerability in Palo Alto Networks PAN-OS software allows a PAN-OS administrator with access to the management web interface to perform actions on the firewall with root privileges.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-9474"}]',
    },
    {
        "cve_id": "CVE-2025-29824",
        "title": "CVE-2025-29824",
        "published_date": "2025-05-31",
        "cvss_score": 9.6,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Ivanti",
        "product": "Endpoint Manager",
        "description_raw": "An unspecified SQL Injection vulnerability in Core server of Ivanti EPM 2022 SU5 and prior allows an unauthenticated attacker within the same network to execute arbitrary code.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-29824"}]',
    },
    {
        "cve_id": "CVE-2025-20353",
        "title": "CVE-2025-20353",
        "published_date": "2025-04-24",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "Cisco",
        "product": "ASA / Firepower Threat Defense",
        "description_raw": "A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the device to reload unexpectedly, resulting in a denial of service (DoS) condition.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-20353"}]',
    },
    {
        "cve_id": "CVE-2025-43573",
        "title": "CVE-2025-43573",
        "published_date": "2025-10-08",
        "cvss_score": 6.5,
        "severity": "MEDIUM",
        "kev": True,
        "source": "NVD",
        "vendor": "Microsoft",
        "product": "Windows MSHTML Platform",
        "description_raw": "Microsoft Windows MSHTML Platform Spoofing Vulnerability that can be exploited to bypass security features.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-43573"}]',
    },
    {
        "cve_id": "CVE-2025-7971",
        "title": "CVE-2025-7971",
        "published_date": "2025-08-21",
        "cvss_score": 8.8,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "Google",
        "product": "Chrome (V8 JavaScript Engine)",
        "description_raw": "Type confusion in V8 in Google Chrome prior to 128.0.6613.84 allowed a remote attacker to exploit heap corruption via a crafted HTML page.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-7971"}]',
    },
    {
        "cve_id": "CVE-2025-30088",
        "title": "CVE-2025-30088",
        "published_date": "2025-06-11",
        "cvss_score": 7.0,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "Microsoft",
        "product": "Windows Kernel",
        "description_raw": "Windows Kernel Elevation of Privilege Vulnerability. A race condition in the Windows kernel allows a local attacker to gain SYSTEM privileges.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-30088"}]',
    },
    {
        "cve_id": "CVE-2025-12356",
        "title": "CVE-2025-12356",
        "published_date": "2025-12-17",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "BeyondTrust",
        "product": "Privileged Remote Access / Remote Support",
        "description_raw": "A critical vulnerability has been discovered in Privileged Remote Access (PRA) and Remote Support (RS) products which can allow an unauthenticated attacker to inject commands that are run as a site user.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-12356"}]',
    },
    {
        "cve_id": "CVE-2025-49138",
        "title": "CVE-2025-49138",
        "published_date": "2025-12-10",
        "cvss_score": 7.8,
        "severity": "HIGH",
        "kev": True,
        "source": "NVD",
        "vendor": "Microsoft",
        "product": "Windows CLFS Driver",
        "description_raw": "Windows Common Log File System Driver Elevation of Privilege Vulnerability. A heap-based buffer overflow allows a local attacker to gain SYSTEM-level privileges.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-49138"}]',
    },
    {
        "cve_id": "CVE-2025-55956",
        "title": "CVE-2025-55956",
        "published_date": "2025-12-13",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "kev": True,
        "source": "NVD",
        "vendor": "Cleo",
        "product": "Harmony / VLTrader / LexiCom",
        "description_raw": "In Cleo Harmony before 5.8.0.24, VLTrader before 5.8.0.24, and LexiCom before 5.8.0.24, an unauthenticated user can import and execute arbitrary Bash or PowerShell commands on the host system by leveraging the default settings of the Autorun directory.",
        "references": '[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-55956"}]',
    },
]

LLM_ANALYSES = {
    "CVE-2025-3400": {
        "summary": "Vulnérabilité critique d'injection de commandes dans PAN-OS GlobalProtect permettant l'exécution de code arbitraire avec les privilèges root, sans authentification. Activement exploitée dans la nature.",
        "impact": "Compromission complète du pare-feu. Un attaquant non authentifié peut prendre le contrôle total de l'équipement réseau, intercepter le trafic, pivoter vers le réseau interne et exfiltrer des données sensibles.",
        "mitigation": "Appliquer immédiatement le correctif Palo Alto Networks. Activer Threat Prevention (Threat ID 95187). Vérifier les indicateurs de compromission. Isoler l'interface de gestion du réseau public.",
    },
    "CVE-2025-21887": {
        "summary": "Injection de commandes dans Ivanti Connect Secure et Policy Secure. Un administrateur authentifié peut exécuter des commandes arbitraires. Exploitée activement en combinaison avec CVE-2023-46805.",
        "impact": "Prise de contrôle complète des passerelles VPN. Les attaquants peuvent accéder aux réseaux internes, voler des identifiants et déployer des portes dérobées persistantes.",
        "mitigation": "Appliquer les correctifs Ivanti. Réinitialiser les appliances compromises selon les instructions de CISA. Révoquer et renouveler tous les certificats et identifiants exposés.",
    },
    "CVE-2025-1709": {
        "summary": "Contournement d'authentification critique dans ConnectWise ScreenConnect permettant un accès direct aux systèmes gérés sans identification préalable.",
        "impact": "Accès non autorisé à tous les endpoints gérés par ScreenConnect. Risque de déploiement de ransomware, vol de données et mouvement latéral massif.",
        "mitigation": "Mettre à jour vers ScreenConnect 23.9.8 ou supérieur immédiatement. Auditer les connexions récentes pour détecter les accès non autorisés.",
    },
    "CVE-2025-4577": {
        "summary": "Vulnérabilité critique dans PHP-CGI sur Windows permettant l'exécution de code via manipulation des paramètres de ligne de commande exploitant le comportement Best-Fit de Windows.",
        "impact": "Exécution de code PHP arbitraire sur le serveur, divulgation du code source des applications, compromission complète du serveur web.",
        "mitigation": "Mettre à jour PHP vers les versions corrigées (8.1.29+, 8.2.20+, 8.3.8+). Migrer de PHP-CGI vers PHP-FPM. Restreindre les pages de code Windows.",
    },
    "CVE-2025-6387": {
        "summary": "Condition de concurrence dans le gestionnaire de signaux du serveur OpenSSH (sshd), nommée regreSSHion. Permet potentiellement l'exécution de code à distance en tant que root.",
        "impact": "Exécution de code à distance avec privilèges root sur les serveurs SSH vulnérables. Exploitation complexe mais risque élevé pour les serveurs exposés sur Internet.",
        "mitigation": "Mettre à jour OpenSSH vers la version 9.8+. Réduire LoginGraceTime. Limiter l'accès SSH via des règles de pare-feu. Surveiller les tentatives de connexion anormales.",
    },
    "CVE-2025-38077": {
        "summary": "Débordement de tampon dans le service de licences Bureau à distance de Windows permettant l'exécution de code à distance sans authentification.",
        "impact": "Compromission complète des serveurs Windows exécutant le service RD Licensing. Prise de contrôle à distance sans interaction utilisateur.",
        "mitigation": "Appliquer les mises à jour Microsoft de juillet 2025. Désactiver le service RD Licensing si non nécessaire. Isoler les serveurs du réseau public.",
    },
    "CVE-2025-23113": {
        "summary": "Vulnérabilité de chaîne de format dans FortiOS, FortiProxy, FortiPAM et FortiSwitchManager permettant l'exécution de code à distance via des paquets spécialement conçus.",
        "impact": "Exécution de code non autorisé sur les équipements Fortinet. Compromission des pare-feux et passerelles de sécurité, exposant le réseau protégé.",
        "mitigation": "Mettre à jour vers les versions corrigées de FortiOS. Restreindre l'accès au protocole FGFM. Surveiller les journaux pour activités suspectes.",
    },
    "CVE-2025-47575": {
        "summary": "Absence d'authentification critique dans le démon fgfmd de FortiManager permettant l'exécution de commandes à distance sans authentification.",
        "impact": "Prise de contrôle de FortiManager gérant potentiellement des centaines de pare-feux. Risque de modification massive des politiques de sécurité.",
        "mitigation": "Appliquer immédiatement le correctif Fortinet. Restreindre les IP autorisées à se connecter au démon fgfmd. Vérifier l'intégrité de la configuration.",
    },
    "CVE-2025-0012": {
        "summary": "Contournement d'authentification dans l'interface de gestion web de PAN-OS permettant d'obtenir des privilèges administrateur complets sans authentification.",
        "impact": "Accès administrateur complet au pare-feu. Modification des règles de sécurité, interception de trafic, accès aux VPN et données de configuration.",
        "mitigation": "Mettre à jour PAN-OS immédiatement. Restreindre l'accès à l'interface de gestion. Activer l'authentification multifacteur.",
    },
    "CVE-2025-21762": {
        "summary": "Écriture hors limites dans FortiOS SSL VPN permettant l'exécution de code à distance via des requêtes HTTP spécialement conçues, sans authentification.",
        "impact": "Compromission complète des passerelles VPN Fortinet. Accès au réseau interne, vol d'identifiants VPN, déploiement de malware.",
        "mitigation": "Mettre à jour FortiOS. Désactiver le SSL VPN si temporairement non nécessaire. Vérifier les indicateurs de compromission publiés par Fortinet.",
    },
    "CVE-2025-28995": {
        "summary": "Vulnérabilité de traversée de répertoire dans SolarWinds Serv-U permettant la lecture de fichiers sensibles sur le serveur hôte.",
        "impact": "Lecture non autorisée de fichiers système, fichiers de configuration et potentiellement de données d'identification.",
        "mitigation": "Mettre à jour SolarWinds Serv-U. Restreindre l'accès réseau au serveur. Auditer les fichiers consultés.",
    },
    "CVE-2025-5910": {
        "summary": "Absence d'authentification critique dans Palo Alto Networks Expedition permettant la prise de contrôle du compte administrateur.",
        "impact": "Accès complet à Expedition contenant les configurations de pare-feu, identifiants et politiques de sécurité.",
        "mitigation": "Mettre à jour Expedition. Restreindre l'accès réseau. Changer tous les identifiants stockés. Auditer les accès récents.",
    },
    "CVE-2025-36401": {
        "summary": "Exécution de code à distance dans GeoServer via l'évaluation d'expressions XPath dans les noms de propriétés, sans authentification.",
        "impact": "Compromission complète du serveur GeoServer. Accès aux données géospatiales, possibilité de pivoter vers d'autres systèmes.",
        "mitigation": "Mettre à jour vers GeoServer 2.23.6 ou 2.24.4. Restreindre l'accès réseau. Surveiller les requêtes OGC suspectes.",
    },
    "CVE-2025-12356": {
        "summary": "Injection de commandes critique dans BeyondTrust PRA et Remote Support. Un attaquant non authentifié peut injecter des commandes exécutées en tant qu'utilisateur du site.",
        "impact": "Compromission des outils d'accès à distance privilégié. Accès potentiel à tous les systèmes gérés via BeyondTrust.",
        "mitigation": "Appliquer immédiatement le correctif. Auditer tous les accès récents. Vérifier l'intégrité des sessions. Activer la journalisation renforcée.",
    },
    "CVE-2025-55956": {
        "summary": "Vulnérabilité critique dans les produits Cleo permettant l'exécution de commandes Bash ou PowerShell via le répertoire Autorun, sans authentification.",
        "impact": "Exécution de code arbitraire sur le serveur hôte. Compromission des systèmes de transfert de fichiers. Risque de ransomware.",
        "mitigation": "Mettre à jour vers Cleo 5.8.0.24+. Désactiver le répertoire Autorun. Surveiller les fichiers déposés dans les répertoires de transfert.",
    },
    "CVE-2025-40711": {
        "summary": "Désérialisation de données non fiables dans Veeam Backup & Replication permettant l'exécution de code à distance sans authentification.",
        "impact": "Compromission du serveur de sauvegarde. Accès aux données de sauvegarde de toute l'infrastructure. Risque de destruction ou chiffrement des sauvegardes.",
        "mitigation": "Mettre à jour Veeam immédiatement. Isoler le serveur de sauvegarde. Vérifier l'intégrité des sauvegardes existantes.",
    },
    "CVE-2025-9474": {
        "summary": "Élévation de privilèges dans PAN-OS permettant à un administrateur authentifié d'exécuter des actions avec les privilèges root.",
        "impact": "Accès root complet, contournement des restrictions de sécurité, installation de backdoors persistantes.",
        "mitigation": "Mettre à jour PAN-OS. Appliquer le principe du moindre privilège. Surveiller les commandes exécutées par les administrateurs.",
    },
    "CVE-2025-29824": {
        "summary": "Injection SQL dans Ivanti Endpoint Manager permettant l'exécution de code arbitraire par un attaquant non authentifié sur le même réseau.",
        "impact": "Compromission du serveur de gestion des endpoints. Accès à tous les postes gérés. Déploiement possible de malware à grande échelle.",
        "mitigation": "Appliquer le correctif Ivanti EPM SU6. Segmenter le réseau. Surveiller le trafic pour les requêtes SQL suspectes.",
    },
    "CVE-2025-20353": {
        "summary": "Déni de service dans Cisco ASA et Firepower Threat Defense. Un attaquant non authentifié peut provoquer le redémarrage inattendu de l'équipement.",
        "impact": "Interruption de service des pare-feux Cisco. Perte temporaire de protection réseau. Exploitation en boucle possible.",
        "mitigation": "Appliquer les mises à jour Cisco. Restreindre l'accès aux interfaces de gestion et VPN. Surveiller les redémarrages anormaux.",
    },
    "CVE-2025-43573": {
        "summary": "Vulnérabilité d'usurpation dans la plateforme Windows MSHTML permettant de contourner les mesures de sécurité du navigateur.",
        "impact": "Contournement des protections du navigateur. Facilitation du phishing et du téléchargement de malware.",
        "mitigation": "Appliquer les mises à jour Microsoft d'octobre 2025. Sensibiliser les utilisateurs au phishing. Déployer un filtrage web.",
    },
    "CVE-2025-7971": {
        "summary": "Confusion de type dans le moteur JavaScript V8 de Chrome permettant la corruption mémoire via une page HTML spécialement conçue.",
        "impact": "Exécution de code arbitraire dans le contexte du navigateur. Compromission potentielle du poste via simple visite d'une page web.",
        "mitigation": "Mettre à jour Chrome vers 128.0.6613.84+. Déployer les mises à jour automatiques. Utiliser l'isolation de site.",
    },
    "CVE-2025-30088": {
        "summary": "Condition de concurrence dans le noyau Windows permettant une élévation de privilèges locale vers SYSTEM.",
        "impact": "Un attaquant local limité peut obtenir les privilèges SYSTEM. Souvent utilisé comme deuxième étape après compromission initiale.",
        "mitigation": "Appliquer les mises à jour Microsoft de juin 2025. Restreindre les accès locaux. Surveiller les processus avec privilèges élevés.",
    },
    "CVE-2025-49138": {
        "summary": "Débordement de tampon dans le pilote CLFS de Windows permettant une élévation de privilèges locale vers SYSTEM.",
        "impact": "Obtention de privilèges SYSTEM. Exploitation active observée, souvent comme composante d'une chaîne d'attaque plus large.",
        "mitigation": "Appliquer les mises à jour Microsoft de décembre 2025. Surveiller les accès aux fichiers journaux CLFS. Déployer un EDR.",
    },
}

# CVEs non analysées (simule le travail partiel de la Personne 2)
UNANALYZED_CVES = ["CVE-2025-50623", "CVE-2025-11680"]


def seed():
    print("=" * 60)
    print("  Vigilant Guardian — Initialisation de la base de démo")
    print("=" * 60)

    print("\n[1/3] Initialisation du schéma...")
    init_db()

    print(f"[2/3] Insertion de {len(SEED_VULNS)} vulnérabilités...")
    for v in SEED_VULNS:
        upsert_vulnerability(v)
        kev_label = " [KEV]" if v["kev"] else ""
        print(f"  + {v['cve_id']}  {v['severity']:>8}  {v['cvss_score'] or 'N/A':>5}{kev_label}")

    analyzed_count = len(LLM_ANALYSES) - len(UNANALYZED_CVES)
    print(f"\n[3/3] Ajout des analyses LLM ({analyzed_count} analysées, {len(UNANALYZED_CVES)} en attente)...")
    for cve_id, analysis in LLM_ANALYSES.items():
        if cve_id not in UNANALYZED_CVES:
            save_llm_analysis(cve_id, analysis["summary"], analysis["impact"], analysis["mitigation"])

    print("\n" + "=" * 60)
    print("  Base de données prête pour la démonstration !")
    print("  Lancez : python app.py")
    print("=" * 60)


if __name__ == "__main__":
    seed()
