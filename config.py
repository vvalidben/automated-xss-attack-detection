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
