"""
verifier.py  (core/verifier.py)
================================
Vérification "preuve par l'exécution" des vulnérabilités détectées par
XSStrike/DalFox.

XSStrike se base sur un score heuristique (similarité de chaîne face à un
WAF) et DalFox sur des heuristiques de reflection : les deux peuvent produire
des faux positifs (payload présent dans la réponse mais jamais réellement
exécuté par un navigateur). Ce module rejoue chaque payload dans un vrai
navigateur **Playwright** : la vulnérabilité n'est marquée `confirmed` que si
un dialogue JS (alert/confirm/prompt) se déclenche réellement — preuve
irréfutable d'exécution. Une capture d'écran est prise dans tous les cas pour
illustrer le rapport (utile aussi pour comprendre un faux positif : la
capture montre le payload neutralisé/échappé sur la page).
"""

from __future__ import annotations

import base64
import logging
import threading
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from playwright.async_api import async_playwright

import config

logger = logging.getLogger("verifier")

# Correspondance best-effort paramètre -> emplacement UI connu (OWASP Juice
# Shop). Purement indicatif : si le paramètre n'est pas dans cette liste, on
# se contente de l'instruction générique (coller l'URL). Aide à répondre
# concrètement à "où" pour les cas les plus fréquents (barre de recherche...).
_UI_HINTS: dict[str, str] = {
    "q": "the search bar (magnifying-glass icon at the top of the app)",
}


async def _snap(page, label: str) -> dict[str, str] | None:
    """Capture un screenshot labellisé (best-effort, jamais bloquant)."""
    try:
        raw = await page.screenshot(full_page=False)
    except Exception:
        return None
    return {"label": label, "image_b64": base64.b64encode(raw).decode("ascii")}


async def _annotate_confirmed(page) -> None:
    """
    Incruste un bandeau visuel avant la capture "résultat" quand l'exécution
    est confirmée (voir core/crawler.py._annotate_confirmed pour le détail :
    un dialogue JS natif n'apparaît jamais sur une capture d'écran, donc sans
    ce bandeau la capture "résultat" peut sembler identique à la capture
    "avant" alors que le payload s'est bien exécuté).
    """
    try:
        await page.evaluate(
            """() => {
                const id = '__xss_poc_confirmed_banner__';
                if (document.getElementById(id)) return;
                const b = document.createElement('div');
                b.id = id;
                b.textContent = '✅ XSS CONFIRMED — a JS dialog '
                    + '(alert/confirm/prompt) just fired here. Native browser dialogs '
                    + 'cannot appear in a screenshot: this banner, added by the tool '
                    + 'afterwards, marks the moment of execution.';
                b.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;'
                    + 'background:#c0392b;color:#fff;font:bold 13px/1.5 sans-serif;'
                    + 'padding:10px 18px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,.5);';
                (document.body || document.documentElement).appendChild(b);
            }"""
        )
    except Exception:
        pass


def _inject_payload_into_url(url: str, parameter: str, payload: str) -> str | None:
    """Reconstruit l'URL en substituant le paramètre vulnérable par le payload."""
    if not url or not parameter:
        return None
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[parameter] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _build_reproduction_steps(vuln: dict[str, Any], test_url: str | None) -> list[str]:
    """
    Reconstruit, en langage clair, la chaîne "comment cette vulnérabilité a
    été trouvée puis OÙ/COMMENT placer le payload pour la rejouer" — à partir
    des champs déjà présents dans `vuln` (tool/parameter/payload/context/
    method/source_page). Sert à documenter la méthodologie dans le rapport,
    pas seulement lister le résultat brut.

    Le point important : GET (paramètre d'URL) et POST (champ de formulaire
    authentifié) ne se rejouent PAS de la même façon. Injecter le payload
    dans la query string d'une URL de formulaire POST donnerait une
    instruction fausse — on distingue donc explicitement les deux cas.
    """
    tool = vuln.get("tool", "")
    param = vuln.get("parameter", "")
    payload = vuln.get("payload", "")
    url = vuln.get("url", "") or "—"
    context = vuln.get("context", "")
    method = (vuln.get("method") or "GET").upper()
    source_page = vuln.get("source_page", "")

    steps: list[str] = []

    if tool == "xsstrike":
        steps.append(
            f"Discovery: the Playwright crawler spotted the URL parameter "
            f"'{param}' on {url} as an injection point (link or GET form)."
        )
        steps.append(
            "Automated test: XSStrike fuzzed this parameter with several "
            "XSS payload variants (context/WAF bypass) and kept the one "
            "with the best efficiency/confidence score."
        )
    elif tool == "dalfox" and method == "POST":
        steps.append(
            f"Discovery: the crawler found a POST form "
            f"(field '{param}') on {source_page or url}, and logged in "
            "with a disposable test account to get a valid session."
        )
        steps.append(
            "Automated test: DalFox replayed the session token in a "
            f"cookie and fuzzed the POST request body sent to {url} "
            "with its payload corpus (including PortSwigger + PayloadBox)."
        )
    elif tool == "dalfox":
        steps.append(
            f"Discovery: the parameter '{param}' on {url} was passed to "
            "DalFox as a testable candidate (parameterized URL intercepted "
            "during the crawl)."
        )
        steps.append(
            "Automated test: DalFox injected a set of XSS payloads and "
            f"detected a reflection in the context: {context or 'unspecified'}."
        )
    else:
        steps.append(f"Injection point identified: parameter '{param}' on {url}.")

    steps.append(
        f"Payload used: {payload}" if payload
        else "No distinct payload associated (heuristic signal from the scanner)."
    )

    if method == "POST":
        where = source_page or url
        steps.append(
            f"WHERE: this is NOT a URL parameter — it's the "
            f"'{param}' field of a POST form, visible on {where}. Pasting "
            "the payload into a URL would not trigger it."
        )
        steps.append(
            f"HOW: log in with a test account, open {where}, "
            f"type the payload directly into the '{param}' field, then "
            "submit the form (save/send button)."
        )
        steps.append(
            "Equivalent technical reproduction (raw request, what "
            f"DalFox did): POST {url} with the session cookie and the "
            f"body '{param}=<payload>'."
        )
    elif test_url:
        hint = _UI_HINTS.get(param)
        steps.append(
            f"WHERE: the browser's address bar (URL parameter '{param}')."
        )
        steps.append(f"HOW: paste this URL and press Enter → {test_url}")
        if hint:
            steps.append(
                f"UI tip: this parameter usually maps to {hint} — "
                "you can also type the payload directly there instead of "
                "editing the URL by hand."
            )
    else:
        steps.append(
            "Manual reproduction isn't possible automatically (missing "
            "parameter or URL) — use the payload and context above to "
            "test by hand."
        )

    return steps


async def _verify_one(browser, vuln: dict[str, Any]) -> None:
    vuln["confirmed"] = False
    vuln["screenshot_b64"] = ""
    vuln["screenshots"] = []
    vuln["verification_note"] = ""

    # Un champ POST (formulaire authentifié) ne se rejoue pas en collant le
    # payload dans une query string : la navigation GET ci-dessous ne
    # frapperait ni le bon endpoint ni le bon contexte. On ne fait donc PAS
    # de vérification navigateur automatique pour ces cas — le signal de
    # confiance reste le fuzzing authentifié effectué par DalFox lui-même.
    if (vuln.get("method") or "GET").upper() == "POST":
        vuln["reproduction_url"] = ""
        vuln["verification_note"] = (
            "Automatic browser verification not applicable: this "
            "payload targets an authenticated POST form field, not a "
            "URL parameter. The confidence signal comes from DalFox's own "
            "authenticated fuzzing (see reproduction steps)."
        )
        vuln["reproduction_steps"] = _build_reproduction_steps(vuln, None)
        return

    test_url = _inject_payload_into_url(
        vuln.get("url", ""), vuln.get("parameter", ""), vuln.get("payload", "")
    )
    vuln["reproduction_url"] = test_url or ""

    if not test_url:
        vuln["verification_note"] = (
            "Verification not possible: missing parameter or URL."
        )
        vuln["reproduction_steps"] = _build_reproduction_steps(vuln, test_url)
        return

    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    dialog_fired = False

    async def _on_dialog(dialog):
        nonlocal dialog_fired
        dialog_fired = True
        try:
            await dialog.dismiss()
        except Exception:
            pass

    page.on("dialog", _on_dialog)

    screenshots: list[dict[str, str]] = []
    try:
        # Capture "avant" : la page originale (non modifiée), pour qu'on
        # puisse comparer visuellement l'état normal vs l'état injecté —
        # une seule image finale ne montre pas le "avant" du "après".
        original_url = vuln.get("url", "")
        if original_url and original_url != test_url:
            try:
                await page.goto(
                    original_url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                await page.wait_for_timeout(800)
                shot = await _snap(page, "Before injection (original page)")
                if shot:
                    screenshots.append(shot)
            except Exception:
                pass  # best-effort: a failed "before" shot doesn't block verification

        await page.goto(
            test_url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
            wait_until="domcontentloaded",
        )
        await page.wait_for_timeout(1500)
        vuln["confirmed"] = dialog_fired
        vuln["verification_note"] = (
            "Payload executed: a JS dialog (alert/confirm/prompt) "
            "actually fired in a real browser." if dialog_fired else
            "No JS execution detected in a real browser: "
            "likely false positive (payload not executable in this context, "
            "e.g. escaped/encoded, or reflected in an unrendered JSON response)."
        )
        if dialog_fired:
            await _annotate_confirmed(page)
        result_shot = await _snap(
            page,
            "Result (payload executed — banner added by the tool)" if dialog_fired
            else "Result (after injection, no execution)",
        )
        if result_shot:
            screenshots.append(result_shot)
        vuln["screenshots"] = screenshots
        vuln["screenshot_b64"] = screenshots[-1]["image_b64"] if screenshots else ""
    except Exception as exc:
        logger.debug("Verification failed for %s: %s", test_url, exc)
        vuln["verification_note"] = f"Verification not possible: {exc}"
        vuln["screenshots"] = screenshots
    finally:
        await context.close()
        steps = _build_reproduction_steps(vuln, test_url)
        if vuln.get("verification_note"):
            steps.append(f"Observed result: {vuln['verification_note']}")
        vuln["reproduction_steps"] = steps


async def verify_vulnerabilities(
    vulnerabilities: list[dict[str, Any]],
    stop_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    """
    Rejoue chaque vulnérabilité (URL + paramètre + payload) dans un vrai
    navigateur et enrichit chaque dict avec :
        - confirmed (bool) : un dialogue JS s'est réellement déclenché,
        - screenshot_b64 (str) : capture d'écran encodée en base64,
        - verification_note (str) : explication lisible du résultat.

    `stop_event` (pause utilisateur) est vérifié entre chaque vulnérabilité :
    celles déjà vérifiées restent enrichies, les suivantes sont laissées
    telles quelles plutôt que de forcer la fin de la vérification en cours.
    """
    if not vulnerabilities:
        return vulnerabilities

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.CRAWLER_HEADLESS)
        try:
            for v in vulnerabilities:
                if stop_event is not None and stop_event.is_set():
                    break
                await _verify_one(browser, v)
        finally:
            await browser.close()

    return vulnerabilities
