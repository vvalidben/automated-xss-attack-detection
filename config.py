"""
config.py
=========
Configuration centralisée du framework.

Toutes les valeurs peuvent être surchargées via des variables d'environnement,
ce qui est pratique pour la soutenance (ex : changer la cible sans toucher au code).
"""

from __future__ import annotations

import os
from pathlib import Path


# --------------------------------------------------------------------------
# Chemins du projet (structure modulaire)
# --------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"      # index.html + report_template.html
REPORTS_DIR: Path = BASE_DIR / "reports"          # rapports générés (HTML/PDF)

# On crée le dossier de sortie s'il n'existe pas encore.
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Historique persistant des scans (survit aux redémarrages du serveur,
# contrairement au registre en mémoire SCANS de app.py).
HISTORY_FILE: Path = REPORTS_DIR / "history.json"
HISTORY_MAX_ENTRIES: int = 100


# --------------------------------------------------------------------------
# Crawler (Playwright)
# --------------------------------------------------------------------------
CRAWLER_MAX_PAGES: int = int(os.getenv("CRAWLER_MAX_PAGES", "40"))
CRAWLER_MAX_DEPTH: int = int(os.getenv("CRAWLER_MAX_DEPTH", "2"))
CRAWLER_PAGE_TIMEOUT_MS: int = int(os.getenv("CRAWLER_PAGE_TIMEOUT_MS", "15000"))
CRAWLER_HEADLESS: bool = os.getenv("CRAWLER_HEADLESS", "true").lower() == "true"
# Rester sur le même domaine que la cible (évite de scanner tout Internet !).
CRAWLER_SAME_ORIGIN_ONLY: bool = True


# --------------------------------------------------------------------------
# Scanners DAST (conteneurs Docker)
# --------------------------------------------------------------------------
# Noms des images construites via les Dockerfile fournis (dossier docker/).
XSSTRIKE_IMAGE: str = os.getenv("XSSTRIKE_IMAGE", "xss-framework/xsstrike:latest")
DALFOX_IMAGE: str = os.getenv("DALFOX_IMAGE", "xss-framework/dalfox:latest")

# Timeout (secondes) au-delà duquel un conteneur de scan est tué.
SCANNER_TIMEOUT_S: int = int(os.getenv("SCANNER_TIMEOUT_S", "180"))

# Réseau Docker : "host" permet aux conteneurs d'atteindre localhost:3000
# (Juice Shop) sous Linux. Sous Docker Desktop (Windows/macOS), on utilise
# plutôt "bridge" + host.docker.internal (voir TARGET_HOST_OVERRIDE).
DOCKER_NETWORK_MODE: str = os.getenv("DOCKER_NETWORK_MODE", "host")

# Hôte à substituer à "localhost" dans les URLs envoyées aux conteneurs.
# - Linux + network_mode=host  -> laisser vide, "localhost" fonctionne
# - Docker Desktop (Win/macOS) -> "host.docker.internal"
TARGET_HOST_OVERRIDE: str = os.getenv("TARGET_HOST_OVERRIDE", "")


# --------------------------------------------------------------------------
# Cible de test par défaut
# --------------------------------------------------------------------------
DEFAULT_TARGET: str = os.getenv("DEFAULT_TARGET", "http://localhost:3000")


# --------------------------------------------------------------------------
# Sévérités & scoring (utilisés par le reporter)
# --------------------------------------------------------------------------
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLORS = {
    "Critical": "#8e0000",
    "High": "#d9534f",
    "Medium": "#f0ad4e",
    "Low": "#5bc0de",
    "Info": "#777777",
}


# --------------------------------------------------------------------------
# Niveaux de scan (choisis par l'utilisateur dans l'UI)
# --------------------------------------------------------------------------
# Chaque niveau règle simultanément : la portée du crawl (pages/profondeur),
# le budget de sondage actif du crawler (DOM-XSS / réfléchi / persisté —
# voir core.crawler), le nombre d'endpoints réellement passés aux scanners
# DAST (core.scanner_manager), si les formulaires POST authentifiés sont
# fuzzés, si le corpus DalFox étendu (PortSwigger + PayloadBox) est chargé,
# et un plafond de vérification navigateur (l'étape la plus coûteuse du
# pipeline : un aller-retour Playwright complet par vulnérabilité).
#
# "Full scan" (niveau 4) reproduit le comportement historique par défaut du
# framework (avant l'introduction des niveaux) ; les niveaux inférieurs
# réduisent progressivement chaque axe pour un scan plus rapide/plus léger.
SCAN_LEVELS: dict[int, dict] = {
    1: {
        "label": "Low",
        "description": (
            "Quick smoke test: a handful of pages, no persisted-form "
            "fuzzing, no authenticated scan."
        ),
        "max_pages": 5, "max_depth": 1,
        "dom_probe_budget": 10, "reflected_probe_budget": 5, "form_probe_budget": 0,
        "header_probe_budget": 0,
        "max_urls": 5, "max_auth_forms": 0,
        "dalfox_remote_payloads": False, "verify_max": 10,
    },
    2: {
        "label": "Normal",
        "description": "Balanced default: moderate crawl depth and payload coverage.",
        "max_pages": 15, "max_depth": 2,
        "dom_probe_budget": 30, "reflected_probe_budget": 15, "form_probe_budget": 10,
        "header_probe_budget": 4,
        "max_urls": 10, "max_auth_forms": 1,
        "dalfox_remote_payloads": False, "verify_max": 25,
    },
    3: {
        "label": "Hard",
        "description": (
            "Thorough: wider crawl, larger payload budget, authenticated "
            "form fuzzing, expanded DalFox corpus."
        ),
        "max_pages": 25, "max_depth": 2,
        "dom_probe_budget": 45, "reflected_probe_budget": 25, "form_probe_budget": 20,
        "header_probe_budget": 8,
        "max_urls": 18, "max_auth_forms": 2,
        "dalfox_remote_payloads": True, "verify_max": 50,
    },
    4: {
        "label": "Full scan",
        "description": (
            "Maximum coverage: full crawl budget, every candidate "
            "endpoint, no verification cap."
        ),
        "max_pages": 40, "max_depth": 2,
        "dom_probe_budget": 60, "reflected_probe_budget": 30, "form_probe_budget": 30,
        "header_probe_budget": 12,
        "max_urls": 20, "max_auth_forms": 2,
        "dalfox_remote_payloads": True, "verify_max": None,
    },
}
DEFAULT_SCAN_LEVEL: int = 2
