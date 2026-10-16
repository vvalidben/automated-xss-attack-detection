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
import threading
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, BackgroundTasks, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import config
from core.crawler import PlaywrightCrawler, DOM_XSS_PAYLOADS
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

# Un threading.Event par scan en cours, vérifié à plusieurs points du
# pipeline (crawler, scanner_manager, verifier — voir chaque module) pour
# permettre au bouton "Pause" de l'UI d'interrompre proprement l'analyse et
# de figer son état (au lieu de la tuer sans laisser de trace exploitable).
SCAN_STOP_EVENTS: dict[str, threading.Event] = {}

# Sérialise l'exécution des pipelines : deux scans concurrents contre la même
# cible (souvent une instance unique comme Juice Shop) se font concurrence
# pour le CPU/l'event-loop Node, ce qui fait timeout le crawl Playwright de
# l'un des deux (Page.goto dépasse CRAWLER_PAGE_TIMEOUT_MS). Un scan lancé
# pendant qu'un autre tourne reste donc à l'état "queued" jusqu'à ce que le
# verrou se libère, au lieu de démarrer en parallèle et d'échouer.
_SCAN_LOCK = asyncio.Lock()


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


def _finalize_pause(
    scan_id: str, target: str, step_label: str,
    crawl_summary: dict[str, Any], vulnerabilities: list[dict[str, Any]],
    scan_meta: dict[str, Any],
) -> None:
    """
    Fige l'état d'un scan interrompu par l'utilisateur (bouton Pause).

    Génère un rapport HTML/PDF PARTIEL avec ce qui a déjà été collecté, pour
    que "où ça s'est arrêté" soit une réponse concrète et consultable — pas
    juste un statut texte perdu au prochain redémarrage.
    """
    state = SCANS[scan_id]
    logger.info("[%s] Analyse mise en pause après : %s", scan_id, step_label)
    try:
        outputs = generate_reports(target, crawl_summary, vulnerabilities, scan_meta)
        state.update(
            status="paused",
            step=f"⏸ Mis en pause après : {step_label}",
            vulnerabilities=vulnerabilities,
            total_vulns=len(vulnerabilities),
            html_path=str(outputs["html"]),
            pdf_path=str(outputs["pdf"]),
            context=outputs["context"],
        )
        ctx = outputs["context"]
        _append_history({
            "id": scan_id,
            "target": target,
            "date": ctx.get("generated_at", ""),
            "status": "paused",
            "total_vulns": len(vulnerabilities),
            "risk_level": ctx.get("risk_level", ""),
            "risk_score": ctx.get("risk_score", 0),
            "html_file": Path(outputs["html"]).name,
            "pdf_file": Path(outputs["pdf"]).name,
        })
    except Exception as exc:  # rapport partiel indisponible : l'état reste consultable via /status
        logger.exception("[%s] Rapport partiel indisponible après pause", scan_id)
        state.update(
            status="paused",
            step=f"⏸ Mis en pause après : {step_label} (rapport indisponible : {exc})",
            vulnerabilities=vulnerabilities,
            total_vulns=len(vulnerabilities),
        )
        _append_history({
            "id": scan_id,
            "target": target,
            "date": "",
            "status": "paused",
            "total_vulns": len(vulnerabilities),
            "risk_level": "",
            "risk_score": 0,
        })


# --------------------------------------------------------------------------
# Pipeline exécuté en tâche de fond
# --------------------------------------------------------------------------
async def run_pipeline(
    scan_id: str, target: str, use_xsstrike: bool, use_dalfox: bool, level: int,
    auth_cookie: str = "", auth_jwt: str = "",
    auth_username: str = "", auth_password: str = "",
) -> None:
    # Le scan reste "queued" (état déjà posé par /scan) tant qu'un autre
    # pipeline détient le verrou : voir le commentaire sur _SCAN_LOCK.
    async with _SCAN_LOCK:
        await _run_pipeline_locked(
            scan_id, target, use_xsstrike, use_dalfox, level,
            auth_cookie, auth_jwt, auth_username, auth_password,
        )


async def _run_pipeline_locked(
    scan_id: str, target: str, use_xsstrike: bool, use_dalfox: bool, level: int,
    auth_cookie: str = "", auth_jwt: str = "",
    auth_username: str = "", auth_password: str = "",
) -> None:
    state = SCANS[scan_id]
    stop_event = threading.Event()
    SCAN_STOP_EVENTS[scan_id] = stop_event
    # Chaque niveau (Low/Normal/Hard/Full scan, choisi dans l'UI) règle la
    # portée du crawl, les budgets de sondage, le nombre d'endpoints DAST, le
    # fuzzing authentifié et le corpus DalFox étendu — voir config.SCAN_LEVELS.
    lvl = config.SCAN_LEVELS[level]
    try:
        # 1) Reconnaissance (Playwright)
        state.update(status="crawling", step=f"Reconnaissance (Playwright) — niveau {lvl['label']}…")
        logger.info("[%s] Crawl de %s (niveau %s)", scan_id, target, lvl["label"])
        crawl_result = await PlaywrightCrawler(
            target, max_pages=lvl["max_pages"], max_depth=lvl["max_depth"],
            stop_event=stop_event,
            dom_probe_budget=lvl["dom_probe_budget"],
            reflected_probe_budget=lvl["reflected_probe_budget"],
            form_probe_budget=lvl["form_probe_budget"],
            header_probe_budget=lvl["header_probe_budget"],
            # Session fournie manuellement (UI) au lieu du compte jetable
            # auto-généré — voir PlaywrightCrawler.run() pour la priorité
            # cookie/JWT > identifiants > auto. Jamais journalisé/persisté
            # tel quel (seul le jeton qui en résulte finit dans le rapport).
            auth_cookie=auth_cookie, auth_jwt=auth_jwt,
            auth_username=auth_username, auth_password=auth_password,
        ).run()

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
            # Inventaire brut des sinks DOM détectés (page/pattern/extrait) :
            # surface "sink" complète, y compris les sinks jamais exploités
            # avec succès — utile pour la section Sources -> Sinks du rapport.
            "dom_sinks_list": [
                {"page": s.page, "pattern": s.pattern, "snippet": s.snippet}
                for s in crawl_result.dom_sinks
            ],
            # Taille du corpus de payloads utilisé pour le sondage actif en
            # navigateur réel (voir core.crawler.DOM_XSS_PAYLOADS) — affiché
            # dans le rapport pour que la couverture réelle soit visible,
            # pas seulement le résultat final.
            "dom_probe_payload_count": len(DOM_XSS_PAYLOADS),
            # Audit de sécurité de la session (cookies HttpOnly/Secure/
            # SameSite, jeton en localStorage — voir crawler._analyze_session).
            # Distinct des vulnérabilités XSS : détermine l'IMPACT d'un XSS
            # trouvé ailleurs, pas une injection en soi. Vide si le login
            # jetable a échoué (site sans formulaire reconnu, etc.).
            "session_analysis": crawl_result.session_analysis,
            # Audit des en-têtes de sécurité HTTP (CSP, X-Frame-Options...)
            # de la page principale — voir crawler._analyze_security_headers.
            # Distinct des vulnérabilités XSS : détermine si le navigateur a
            # un filet de sécurité même quand une injection est confirmée.
            "security_headers": crawl_result.security_headers,
        }
        state.update(crawl_summary=crawl_summary)

        if stop_event.is_set():
            _finalize_pause(
                scan_id, target, "Reconnaissance (Playwright)",
                crawl_summary, list(crawl_result.dom_xss_findings),
                {
                    "scanners": [t for t, on in
                                 (("XSStrike", use_xsstrike), ("DalFox", use_dalfox)) if on],
                    "urls_scanned": 0, "warnings": [], "coverage": {}, "level": lvl["label"],
                },
            )
            return

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
            lvl["max_urls"], stop_event, lvl["dalfox_remote_payloads"],
        )

        # 2bis) DalFox authentifié (POST) sur les formulaires découverts.
        # `scan_targets` ne teste que des URLs GET anonymes : un champ de
        # formulaire POST protégé par une session (ex : nom d'utilisateur
        # sur /profile) lui est invisible. Si le crawler a réussi à se
        # connecter (voir crawler._register_and_login), on rejoue le jeton
        # de session pour laisser DalFox fuzzer ces formulaires avec son
        # corpus de payloads — plus large que ce qu'un test manuel couvre.
        # Borné par le niveau de scan (config.SCAN_LEVELS[level]["max_auth_forms"]).
        MAX_AUTH_FORMS = lvl["max_auth_forms"]
        SKIP_FIELD_TYPES = {"email", "password", "hidden", "file", "checkbox", "radio", "submit"}
        auth_forms_scanned = 0
        if (MAX_AUTH_FORMS > 0 and use_dalfox and crawl_result.auth_token
                and crawl_result.forms and not stop_event.is_set()):
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
                if stop_event.is_set():
                    break
                post_data = "&".join(f"{name}=x" for name in fuzzable)
                logger.info("[%s] DalFox authentifié (POST) sur %s (%s)",
                            scan_id, form.action, post_data)
                scan_results.append(
                    await asyncio.to_thread(
                        manager.run_dalfox_authenticated_post,
                        form.action, post_data, crawl_result.auth_token,
                        "token", form.source_page, stop_event,
                        lvl["dalfox_remote_payloads"],
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
            "level": lvl["label"],
        }

        if stop_event.is_set():
            _finalize_pause(
                scan_id, target, "Scans DAST (XSStrike / DalFox)",
                crawl_summary, vulnerabilities + crawl_result.dom_xss_findings, scan_meta,
            )
            return

        # 3bis) Vérification "preuve par l'exécution" (navigateur réel) :
        # XSStrike/DalFox se basent sur des heuristiques et peuvent produire
        # des faux positifs. On rejoue chaque payload dans Playwright et on
        # ne considère la vulnérabilité confirmée que si un dialogue JS
        # (alert/confirm/prompt) se déclenche réellement. Coût le plus élevé
        # du pipeline (un aller-retour navigateur par vulnérabilité) : plafonné
        # par le niveau de scan (verify_max) sur les niveaux légers — le reste
        # est listé tel quel, non vérifié, plutôt que d'allonger le scan.
        verify_cap = lvl["verify_max"]
        if vulnerabilities:
            state.update(status="verifying", step="Vérification par navigateur réel…")
            if verify_cap is not None and len(vulnerabilities) > verify_cap:
                to_verify, rest = vulnerabilities[:verify_cap], vulnerabilities[verify_cap:]
                for v in rest:
                    v["verification_note"] = (
                        f"Not verified: browser-verification cap reached for the "
                        f"'{lvl['label']}' scan level ({verify_cap} vulnerabilities)."
                    )
                verified = await verify_vulnerabilities(to_verify, stop_event=stop_event)
                vulnerabilities = verified + rest
            else:
                vulnerabilities = await verify_vulnerabilities(vulnerabilities, stop_event=stop_event)

        if stop_event.is_set():
            _finalize_pause(
                scan_id, target, "Vérification par navigateur réel",
                crawl_summary, vulnerabilities + crawl_result.dom_xss_findings, scan_meta,
            )
            return

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
    finally:
        # Le verrou n'a plus de raison d'exister une fois le pipeline terminé
        # (succès, erreur ou pause) : une pause déjà traitée ne doit pas
        # rester "armée" pour un scan futur qui réutiliserait par erreur ce
        # scan_id (uuid4, donc en pratique jamais, mais on évite la fuite).
        SCAN_STOP_EVENTS.pop(scan_id, None)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "default_target": config.DEFAULT_TARGET,
            "scan_levels": config.SCAN_LEVELS,
            "default_scan_level": config.DEFAULT_SCAN_LEVEL,
        },
    )


@app.post("/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    target: str = Form(...),
    use_xsstrike: bool = Form(True),
    use_dalfox: bool = Form(True),
    level: int = Form(config.DEFAULT_SCAN_LEVEL),
    # Authentification manuelle (optionnelle) : session cookie et/ou JWT
    # récupérés depuis un navigateur déjà connecté, OU identifiants d'un
    # compte de test existant — alternative au compte jetable auto-généré.
    # Voir PlaywrightCrawler.run() pour l'ordre de priorité entre les trois.
    auth_cookie: str = Form(""),
    auth_jwt: str = Form(""),
    auth_username: str = Form(""),
    auth_password: str = Form(""),
):
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="L'URL doit commencer par http:// ou https://")
    if level not in config.SCAN_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"Niveau invalide : {level} (attendu {sorted(config.SCAN_LEVELS)})",
        )

    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = {
        "id": scan_id, "target": target, "status": "queued",
        "step": "En file d'attente…", "vulnerabilities": [], "total_vulns": 0,
    }
    background_tasks.add_task(
        run_pipeline, scan_id, target, use_xsstrike, use_dalfox, level,
        auth_cookie.strip(), auth_jwt.strip(), auth_username.strip(), auth_password,
    )
    return JSONResponse({"scan_id": scan_id})


@app.get("/levels")
async def scan_levels():
    """Expose les niveaux de scan disponibles (label + description) pour l'UI."""
    return {
        str(n): {"label": lvl["label"], "description": lvl["description"]}
        for n, lvl in config.SCAN_LEVELS.items()
    }


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
        # Un scan "paused" n'a un rapport que si _finalize_pause a réussi à le
        # générer (voir son except) : l'UI s'en sert pour savoir si elle peut
        # afficher les liens Voir/Télécharger.
        "has_report": bool(state.get("html_path")),
    }


@app.post("/scan/{scan_id}/pause")
async def pause_scan(scan_id: str):
    """
    Demande l'arrêt d'un scan en cours. Ne tue rien de force : positionne un
    `threading.Event` que le pipeline (crawler / scanner_manager / verifier)
    vérifie à ses points de contrôle et honore dès que possible, puis fige
    l'état + génère un rapport partiel (voir _finalize_pause).
    """
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if state["status"] in ("done", "error", "paused"):
        return JSONResponse({"ok": False, "detail": "Ce scan n'est plus en cours."})
    ev = SCAN_STOP_EVENTS.get(scan_id)
    if not ev:
        raise HTTPException(status_code=409, detail="Ce scan n'a pas encore démarré.")
    ev.set()
    state["step"] = f"{state.get('step', '')} — pause demandée…"
    return JSONResponse({"ok": True})


@app.get("/history")
async def history():
    """Historique persistant des scans (survit aux redémarrages du serveur)."""
    return _load_history()


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def view_report(scan_id: str):
    state = SCANS.get(scan_id)
    if not state:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if state["status"] not in ("done", "paused") or not state.get("html_path"):
        raise HTTPException(status_code=409, detail="Le rapport n'est pas encore prêt")
    html_path = Path(state["html_path"])
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/download/{scan_id}")
async def download_pdf(scan_id: str):
    state = SCANS.get(scan_id)
    if not state or state.get("status") not in ("done", "paused") or not state.get("pdf_path"):
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
