"""
app.py
======
Interface web **FastAPI** du XSS Automation Framework.

Fonctionnalités :
    * Formulaire de saisie de l'URL cible (GET /).
    * Lancement d'une analyse asynchrone en tâche de fond (POST /scan).
    * Suivi de l'état d'un scan (GET /status/{scan_id}).
    * Consultation du rapport HTML (GET /report/{scan_id}).
    * Téléchargement du PDF (GET /download/{scan_id}).

Le pipeline complet est : crawler (Playwright) -> scanner_manager (Docker) ->
parser -> reporter (HTML + PDF).

Lancement (depuis la RACINE du projet) :
    uvicorn app:app --reload --port 8000
Puis ouvrir http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, BackgroundTasks, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from core.crawler import PlaywrightCrawler
from core.scanner_manager import ScannerManager
from core.parser import parse_scan_results
from core.verifier import verify_vulnerabilities
from core.reporter import generate_reports

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("app")

app = FastAPI(title="XSS Automation Framework", version="1.0.0")
templates = Jinja2Templates(directory=str(config.TEMPLATES_DIR))
# Sert directement les rapports HTML/PDF déjà générés (utile pour
# l'historique : ces fichiers restent accessibles après un redémarrage du
# serveur, alors que le registre en mémoire SCANS, lui, est reperdu).
app.mount("/files", StaticFiles(directory=str(config.REPORTS_DIR)), name="files")

# Registre en mémoire des scans (suffisant pour une démo mono-utilisateur).
# En production on utiliserait Redis / une base de données.
SCANS: dict[str, dict[str, Any]] = {}


# --------------------------------------------------------------------------
# Historique persistant (fichier JSON) : survit aux redémarrages, à la
# différence de SCANS. Utilisé pour afficher l'historique des scans dans
# l'interface même après un restart du serveur.
# --------------------------------------------------------------------------
def _load_history() -> list[dict[str, Any]]:
    if not config.HISTORY_FILE.exists():
        return []
    try:
        return json.loads(config.HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def _append_history(entry: dict[str, Any]) -> None:
    history = _load_history()
    history.insert(0, entry)
    history = history[: config.HISTORY_MAX_ENTRIES]
    try:
        config.HISTORY_FILE.write_text(
            json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError:
        logger.exception("Impossible d'écrire l'historique des scans")


# --------------------------------------------------------------------------
# Pipeline exécuté en tâche de fond
# --------------------------------------------------------------------------
async def run_pipeline(scan_id: str, target: str, use_xsstrike: bool, use_dalfox: bool) -> None:
    state = SCANS[scan_id]
    try:
        # 1) Reconnaissance (Playwright)
        state.update(status="crawling", step="Reconnaissance (Playwright)…")
        logger.info("[%s] Crawl de %s", scan_id, target)
        crawl_result = await PlaywrightCrawler(target).run()

        candidate_urls = crawl_result.injectable_urls or crawl_result.urls or [target]
        crawl_summary = {
            "pages": len(crawl_result.urls),
            "injectable_urls": len(crawl_result.injectable_urls),
            "forms": len(crawl_result.forms),
            "dom_sinks": len(crawl_result.dom_sinks),
            "dom_xss_confirmed": len(crawl_result.dom_xss_findings),
            # Listes complètes (pas seulement les compteurs) pour que le
            # rapport puisse afficher les endpoints réellement scannés.
            "urls_list": crawl_result.urls,
            "injectable_urls_list": crawl_result.injectable_urls,
        }
        state.update(crawl_summary=crawl_summary)

        # 2) Scans DAST (Docker)
        state.update(status="scanning", step="Scans DAST (XSStrike / DalFox)…")
        manager = ScannerManager()
        # `scan_targets` est une méthode SYNCHRONE et bloquante (elle attend
        # les conteneurs Docker via `container.wait()`). L'appeler directement
        # depuis cette coroutine gèlerait TOUTE la boucle asyncio du serveur
        # pendant toute la durée des scans (plusieurs minutes) : plus aucune
        # requête HTTP — même /status d'un autre scan — ne serait servie
        # entre-temps. `asyncio.to_thread` la déporte dans un thread dédié
        # pour garder le serveur réactif.
        scan_results = await asyncio.to_thread(
            manager.scan_targets, candidate_urls, use_xsstrike, use_dalfox,
        )

        # 2bis) DalFox authentifié (POST) sur les formulaires découverts.
        # `scan_targets` ne teste que des URLs GET anonymes : un champ de
        # formulaire POST protégé par une session (ex : nom d'utilisateur
        # sur /profile) lui est invisible. Si le crawler a réussi à se
        # connecter (voir crawler._register_and_login), on rejoue le jeton
        # de session pour laisser DalFox fuzzer ces formulaires avec son
        # corpus de payloads — plus large que ce qu'un test manuel couvre.
        # Borné à 2 formulaires pour rester rapide.
        MAX_AUTH_FORMS = 2
        SKIP_FIELD_TYPES = {"email", "password", "hidden", "file", "checkbox", "radio", "submit"}
        auth_forms_scanned = 0
        if use_dalfox and crawl_result.auth_token and crawl_result.forms:
            # Filtrer les champs exploitables AVANT de tronquer à
            # MAX_AUTH_FORMS : sinon un formulaire d'upload de fichier (sans
            # aucun champ testable) peut consommer la limite et masquer un
            # formulaire réellement pertinent plus loin dans la liste.
            fuzzable_forms = [
                (f, [fld.name for fld in f.fields if fld.type not in SKIP_FIELD_TYPES])
                for f in crawl_result.forms if f.method.lower() == "post"
            ]
            fuzzable_forms = [(f, names) for f, names in fuzzable_forms if names][:MAX_AUTH_FORMS]
            for form, fuzzable in fuzzable_forms:
                post_data = "&".join(f"{name}=x" for name in fuzzable)
                logger.info("[%s] DalFox authentifié (POST) sur %s (%s)",
                            scan_id, form.action, post_data)
                scan_results.append(
                    await asyncio.to_thread(
                        manager.run_dalfox_authenticated_post,
                        form.action, post_data, crawl_result.auth_token,
                    )
                )
                auth_forms_scanned += 1

        # Remonter une éventuelle erreur d'orchestration (Docker éteint…).
        orch_errors = [r.error for r in scan_results if getattr(r, "error", None)]

        # 3) Parsing
        state.update(status="parsing", step="Analyse des résultats…")
        vulnerabilities = parse_scan_results(scan_results)

        # Couverture par outil : le rapport ne doit pas donner l'impression
        # qu'un scanner "n'a pas tourné" simplement parce qu'il n'a rien
        # trouvé — DalFox en particulier revient très souvent bredouille
        # (payloads correctement filtrés côté serveur), ce qui est un
        # résultat négatif utile, pas une absence d'exécution.
        findings_by_tool = Counter(v.get("tool") for v in vulnerabilities)
        scan_coverage = {
            tool: {
                "tested": sum(1 for r in scan_results if r.tool == tool and not r.error),
                "findings": findings_by_tool.get(tool, 0),
            }
            for tool in {"xsstrike", "dalfox"}
        }
        scan_coverage["dalfox"]["authenticated_forms_tested"] = auth_forms_scanned

        scan_meta = {
            "scanners": [t for t, on in
                         (("XSStrike", use_xsstrike), ("DalFox", use_dalfox)) if on],
            "urls_scanned": len(candidate_urls) + auth_forms_scanned,
            "warnings": orch_errors,
            "coverage": scan_coverage,
        }

        # 3bis) Vérification "preuve par l'exécution" (navigateur réel) :
        # XSStrike/DalFox se basent sur des heuristiques et peuvent produire
        # des faux positifs. On rejoue chaque payload dans Playwright et on
        # ne considère la vulnérabilité confirmée que si un dialogue JS
        # (alert/confirm/prompt) se déclenche réellement.
        if vulnerabilities:
            state.update(status="verifying", step="Vérification par navigateur réel…")
            vulnerabilities = await verify_vulnerabilities(vulnerabilities)

        # 3ter) DOM-XSS confirmés pendant le crawl (voir _probe_dom_xss) :
        # déjà prouvés par exécution réelle (alert() déclenché), on les ajoute
        # tels quels, sans repasser par le vérificateur.
        vulnerabilities.extend(crawl_result.dom_xss_findings)

        # 4) Rapports
        state.update(status="reporting", step="Génération des rapports…")
        outputs = generate_reports(target, crawl_summary, vulnerabilities, scan_meta)

        state.update(
            status="done",
            step="Terminé",
            vulnerabilities=vulnerabilities,
            total_vulns=len(vulnerabilities),
            html_path=str(outputs["html"]),
            pdf_path=str(outputs["pdf"]),
            context=outputs["context"],
        )
        logger.info("[%s] Pipeline terminé : %d vulnérabilités", scan_id, len(vulnerabilities))

        ctx = outputs["context"]
        _append_history({
            "id": scan_id,
            "target": target,
            "date": ctx.get("generated_at", ""),
            "status": "done",
            "total_vulns": len(vulnerabilities),
            "risk_level": ctx.get("risk_level", ""),
            "risk_score": ctx.get("risk_score", 0),
            "html_file": Path(outputs["html"]).name,
            "pdf_file": Path(outputs["pdf"]).name,
        })

    except Exception as exc:  # tout échec est capturé pour ne pas figer l'UI
        logger.exception("[%s] Échec du pipeline", scan_id)
        state.update(status="error", step=f"Erreur : {exc}", error=str(exc))
        _append_history({
            "id": scan_id,
            "target": target,
            "date": "",
            "status": "error",
            "total_vulns": 0,
            "risk_level": "",
            "risk_score": 0,
            "error": str(exc),
        })


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "default_target": config.DEFAULT_TARGET},
    )


@app.post("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    target: str = Form(...),
    use_xsstrike: bool = Form(True),
    use_dalfox: bool = Form(True),
):
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="L'URL doit commencer par http:// ou https://")

    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = {
        "id": scan_id, "target": target, "status": "queued",
        "step": "En file d'attente…", "vulnerabilities": [], "total_vulns": 0,
    }
    background_tasks.add_task(run_pipeline, scan_id, target, use_xsstrike, use_dalfox)
    return JSONResponse({"scan_id": scan_id})


@app.get("/status/{scan_id}")
async def scan_status(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    # On ne renvoie que l'essentiel (pas le contexte complet, volumineux).
    return {
        "id": state["id"],
        "status": state["status"],
        "step": state.get("step", ""),
        "total_vulns": state.get("total_vulns", 0),
        "error": state.get("error"),
    }


@app.get("/history")
async def history():
    """Historique persistant des scans (survit aux redémarrages du serveur)."""
    return _load_history()


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def view_report(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if state["status"] != "done":
        raise HTTPException(status_code=409, detail="Le rapport n'est pas encore prêt")
    html_path = Path(state["html_path"])
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/download/{scan_id}")
async def download_pdf(scan_id: str):
    state = SCANS.get(scan_id)
    if not state or state.get("status") != "done":
        raise HTTPException(status_code=404, detail="Rapport PDF indisponible")
    pdf_path = Path(state["pdf_path"])
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Fichier PDF introuvable")
    return FileResponse(
        pdf_path, media_type="application/pdf",
        filename=f"rapport_xss_{scan_id}.pdf",
    )


@app.get("/health")
async def health():
    """Vérifie la disponibilité de Docker (utile avant une démo)."""
    mgr = ScannerManager()
    return {"docker_available": mgr._docker_ok}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
