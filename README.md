# 🛡️ XSS Automation Framework

Plateforme **DAST** (Dynamic Application Security Testing) d'automatisation de la
détection des attaques **XSS (Cross-Site Scripting)**, développée dans le cadre
d'un projet de stage académique en DevSecOps / Application Security.

Elle orchestre un pipeline complet : reconnaissance JS-aware (**Playwright**),
scans par deux outils DAST spécialisés (**XSStrike** & **DalFox**) exécutés dans
des conteneurs **Docker** isolés, normalisation des résultats, puis génération de
rapports **HTML interactifs** et **PDF professionnels**.

> ⚠️ **Usage légal uniquement.** Ce framework ne doit être utilisé que contre des
> cibles dont vous possédez l'autorisation explicite (typiquement OWASP Juice
> Shop, exécuté en local pour la démonstration).

---

## 1. Architecture & flux de données

```
                    ┌────────────────────────────────────────────┐
                    │            Interface FastAPI (app.py)        │
                    │   Formulaire URL  →  suivi  →  rapport/PDF    │
                    └───────────────┬──────────────────────────────┘
                                    │ (tâche de fond)
        ┌───────────────────────────┼──────────────────────────────┐
        ▼                           ▼                              ▼
┌──────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  crawler.py  │  URLs /  │ scanner_manager  │  brut    │    parser.py     │
│ (Playwright) │ formul.  │   (SDK Docker)   │ ───────▶ │ (LXML / BS4)     │
│ JS-aware,    │ ───────▶ │  ┌────────────┐  │          │ normalisation +  │
│ sinks DOM    │          │  │ XSStrike   │  │          │ déduplication    │
└──────────────┘          │  │ (conteneur)│  │          └────────┬─────────┘
                          │  ├────────────┤  │                   │ vulnérabilités
                          │  │ DalFox     │  │                   ▼
                          │  │ (conteneur)│  │          ┌──────────────────┐
                          │  └────────────┘  │          │   reporter.py    │
                          └──────────────────┘          │ Jinja2 (HTML) +  │
                                                         │ ReportLab (PDF)  │
                                                         └──────────────────┘
```

**Étapes du pipeline :**

1. **Interface (FastAPI)** — l'utilisateur saisit l'URL cible et choisit les
   scanners. Le scan tourne en tâche de fond ; l'UI interroge `/status` en
   polling et propose ensuite le rapport HTML et le PDF.
2. **Crawler (Playwright)** — rend réellement le JavaScript (essentiel pour les
   SPA comme Juice Shop), découvre les URLs internes, extrait les formulaires
   (points d'injection) et repère les *sinks* DOM-XSS (`innerHTML`,
   `document.write`, `eval`…). Il n'injecte rien : il cartographie la surface.
3. **Scanner Manager (SDK Docker)** — pour chaque URL candidate, lance XSStrike
   et DalFox dans des conteneurs jetables, en parallèle, avec timeouts stricts
   et nettoyage systématique.
4. **Parser (LXML / BeautifulSoup)** — convertit les sorties hétérogènes (texte
   XSStrike, JSON DalFox) en un schéma unique `Vulnerability`, déduplique et
   attribue une sévérité.
5. **Reporter (Jinja2 + ReportLab)** — produit un rapport HTML interactif et un
   PDF avec métriques, graphes d'impact (camembert + histogramme) et détail des
   vulnérabilités.

---

## 2. Arborescence du projet

```
automatisation des attaques xss/
├── app.py                    # Interface web (FastAPI)
├── config.py                 # Configuration centralisée
├── requirements.txt          # Dépendances Python
├── README.md
├── core/
│   ├── __init__.py
│   ├── crawler.py            # Module Playwright (découverte URLs/formulaires)
│   ├── scanner_manager.py    # Orchestrateur Docker (XSStrike & DalFox)
│   ├── parser.py             # Parsing LXML/BeautifulSoup des résultats
│   └── reporter.py           # Rapports HTML (Jinja2) + PDF (ReportLab)
├── templates/
│   ├── index.html            # UI (formulaire de saisie)
│   └── report_template.html  # Gabarit du rapport HTML
├── docker/
│   ├── Dockerfile.xsstrike
│   └── Dockerfile.dalfox
└── reports/                  # (créé automatiquement) rapports générés
```

> ℹ️ Les modules de `core/` importent `config` en absolu : **lance toujours les
> commandes depuis la racine du projet** (là où se trouvent `app.py` et
> `config.py`) pour que les imports fonctionnent.

---

## 3. Guide de démarrage rapide

### Prérequis
- Python **3.10+**
- **Docker** installé et démarré (`docker --version`)
- ~2 Go d'espace disque (images des scanners + navigateur Playwright)

### Étape 1 — Lancer la cible de test (OWASP Juice Shop)

```bash
docker run -d -p 3000:3000 --name juiceshop --restart unless-stopped \
  -e NODE_OPTIONS="--max-old-space-size=4096" bkimminich/juice-shop
```

Vérifie qu'elle répond sur http://localhost:3000

### Étape 2 — Construire les images des scanners (depuis la racine du projet)

```bash
docker build -f docker/Dockerfile.xsstrike -t xss-framework/xsstrike:latest .
docker build -f docker/Dockerfile.dalfox  -t xss-framework/dalfox:latest  .
```

### Étape 3 — Installer les dépendances Python

```bash
python -m venv venv
# Linux / macOS :
source venv/bin/activate
# Windows :
venv\Scripts\activate

pip install -r requirements.txt

# Navigateur pour Playwright (télécharge Chromium)
playwright install chromium
```

### Étape 4 — (Docker Desktop uniquement, Windows/macOS)

Sous Docker Desktop, un conteneur ne voit pas `localhost` de l'hôte. Exporte :

```powershell
# Windows (PowerShell)
$env:TARGET_HOST_OVERRIDE="host.docker.internal"
$env:DOCKER_NETWORK_MODE="bridge"
```
```bash
# Linux/macOS — souvent inutile sous Linux natif (network_mode=host)
export TARGET_HOST_OVERRIDE="host.docker.internal"
export DOCKER_NETWORK_MODE="bridge"
```

### Étape 5 — Lancer l'application (depuis la racine du projet)

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

Ouvre **http://localhost:8000**, saisis `http://localhost:3000`, lance l'analyse,
puis consulte le rapport HTML et télécharge le PDF.

> 💡 Vérifie que Docker est bien vu par l'app : http://localhost:8000/health
> doit renvoyer `{"docker_available": true}`.

---

## 4. Configuration (variables d'environnement)

| Variable                 | Défaut                          | Description                                   |
|--------------------------|---------------------------------|-----------------------------------------------|
| `DEFAULT_TARGET`         | `http://localhost:3000`         | Cible pré-remplie dans l'UI                    |
| `CRAWLER_MAX_PAGES`      | `40`                            | Nombre max de pages crawlées                   |
| `CRAWLER_MAX_DEPTH`      | `2`                             | Profondeur max du crawl                        |
| `CRAWLER_HEADLESS`       | `true`                          | Navigateur sans interface                      |
| `SCANNER_TIMEOUT_S`      | `180`                           | Timeout par conteneur de scan (s)              |
| `DOCKER_NETWORK_MODE`    | `host`                          | Mode réseau Docker (`host` / `bridge`)         |
| `TARGET_HOST_OVERRIDE`   | *(vide)*                        | Ex : `host.docker.internal` (Docker Desktop)   |
| `XSSTRIKE_IMAGE`         | `xss-framework/xsstrike:latest` | Nom de l'image XSStrike                         |
| `DALFOX_IMAGE`           | `xss-framework/dalfox:latest`   | Nom de l'image DalFox                          |

---

## 5. Modules — test individuel

Chaque module est exécutable seul pour le débogage / la démonstration
(**depuis la racine**, avec `-m` pour respecter le package `core`) :

```bash
python -m core.crawler http://localhost:3000    # test du crawler seul
python -m core.scanner_manager                   # test d'un scan Docker
python -m core.parser                            # test unitaire du parseur
```

Vérifier la syntaxe de tout le projet :

```bash
python -m py_compile app.py config.py core/*.py
```

---

## 6. Dépannage

| Symptôme                                   | Cause probable / solution                                        |
|--------------------------------------------|------------------------------------------------------------------|
| `/health` renvoie `docker_available:false` | Docker n'est pas démarré, ou l'utilisateur n'a pas les droits.   |
| `Image Docker introuvable`                 | Les images n'ont pas été construites (étape 2).                  |
| `ModuleNotFoundError: config`              | Tu n'as pas lancé la commande depuis la racine du projet.       |
| Scans vides alors que Juice Shop répond    | Sous Docker Desktop, définis `TARGET_HOST_OVERRIDE`.            |
| Crawl très lent / timeouts                 | Réduis `CRAWLER_MAX_PAGES` / augmente `CRAWLER_PAGE_TIMEOUT_MS`. |
| `playwright` : navigateur manquant         | Lance `playwright install chromium`.                            |

---

## 7. Avertissement éthique

Ce framework est un outil pédagogique de **sécurité défensive** : il aide à
identifier des vulnérabilités XSS afin de les corriger. Toute utilisation contre
un système sans autorisation écrite est illégale. Les auteurs déclinent toute
responsabilité en cas d'usage abusif.
