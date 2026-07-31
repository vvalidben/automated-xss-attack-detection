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
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from playwright.async_api import async_playwright

import config

logger = logging.getLogger("verifier")


def _inject_payload_into_url(url: str, parameter: str, payload: str) -> str | None:
    """Reconstruit l'URL en substituant le paramètre vulnérable par le payload."""
    if not url or not parameter:
        return None
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[parameter] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _verify_one(browser, vuln: dict[str, Any]) -> None:
    test_url = _inject_payload_into_url(
        vuln.get("url", ""), vuln.get("parameter", ""), vuln.get("payload", "")
    )
    vuln["confirmed"] = False
    vuln["screenshot_b64"] = ""
    vuln["verification_note"] = ""

    if not test_url:
        vuln["verification_note"] = (
            "Vérification impossible : paramètre ou URL manquant."
        )
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

    try:
        await page.goto(
            test_url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
            wait_until="domcontentloaded",
        )
        await page.wait_for_timeout(1500)
        vuln["confirmed"] = dialog_fired
        vuln["verification_note"] = (
            "Payload exécuté : une boîte de dialogue JS (alert/confirm/prompt) "
            "s'est déclenchée dans un vrai navigateur." if dialog_fired else
            "Aucune exécution JS détectée dans un vrai navigateur : "
            "probable faux positif (payload non exécutable dans ce contexte, "
            "ex. échappé/encodé, ou reflété dans une réponse JSON non rendue)."
        )
        screenshot_bytes = await page.screenshot(full_page=False)
        vuln["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode("ascii")
    except Exception as exc:
        logger.debug("Vérification impossible pour %s : %s", test_url, exc)
        vuln["verification_note"] = f"Vérification impossible : {exc}"
    finally:
        await context.close()


async def verify_vulnerabilities(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Rejoue chaque vulnérabilité (URL + paramètre + payload) dans un vrai
    navigateur et enrichit chaque dict avec :
        - confirmed (bool) : un dialogue JS s'est réellement déclenché,
        - screenshot_b64 (str) : capture d'écran encodée en base64,
        - verification_note (str) : explication lisible du résultat.
    """
    if not vulnerabilities:
        return vulnerabilities

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=config.CRAWLER_HEADLESS)
        try:
            for v in vulnerabilities:
                await _verify_one(browser, v)
        finally:
            await browser.close()

    return vulnerabilities
