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

# Correspondance best-effort paramètre -> emplacement UI connu (OWASP Juice
# Shop). Purement indicatif : si le paramètre n'est pas dans cette liste, on
# se contente de l'instruction générique (coller l'URL). Aide à répondre
# concrètement à "où" pour les cas les plus fréquents (barre de recherche...).
_UI_HINTS: dict[str, str] = {
    "q": "la barre de recherche (icône loupe en haut de l'application)",
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
                b.textContent = '✅ XSS CONFIRME — une boite de dialogue JS '
                    + '(alert/confirm/prompt) vient de se declencher ici. Les dialogues '
                    + 'natifs du navigateur ne peuvent pas apparaitre sur une capture '
                    + 'd\\'ecran : ce bandeau, ajoute par l\\'outil apres coup, marque le '
                    + 'moment de l\\'execution.';
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
            f"Découverte : le crawler Playwright a repéré le paramètre d'URL "
            f"'{param}' sur {url} comme point d'injection (lien ou formulaire GET)."
        )
        steps.append(
            "Test automatisé : XSStrike a fuzzé ce paramètre avec plusieurs "
            "variantes de payloads XSS (contournement de contexte/WAF) et "
            "retenu celle au meilleur score d'efficacité/confiance."
        )
    elif tool == "dalfox" and method == "POST":
        steps.append(
            f"Découverte : le crawler a trouvé un formulaire POST "
            f"(champ '{param}') sur {source_page or url}, et s'est connecté "
            "avec un compte de test jetable pour obtenir une session valide."
        )
        steps.append(
            "Test automatisé : DalFox a rejoué le jeton de session dans un "
            f"cookie et fuzzé le corps de la requête POST envoyée à {url} "
            "avec son corpus de payloads (dont PortSwigger + PayloadBox)."
        )
    elif tool == "dalfox":
        steps.append(
            f"Découverte : le paramètre '{param}' sur {url} a été transmis à "
            "DalFox comme candidat testable (URL paramétrée interceptée "
            "pendant le crawl)."
        )
        steps.append(
            "Test automatisé : DalFox a injecté un jeu de payloads XSS et "
            f"détecté une réflexion dans le contexte : {context or 'non précisé'}."
        )
    else:
        steps.append(f"Point d'injection identifié : paramètre '{param}' sur {url}.")

    steps.append(
        f"Payload retenu : {payload}" if payload
        else "Aucun payload distinct associé (signal heuristique du scanner)."
    )

    if method == "POST":
        where = source_page or url
        steps.append(
            f"OÙ : ce n'est PAS un paramètre d'URL — c'est le champ "
            f"'{param}' d'un formulaire POST, visible sur {where}. Coller "
            "le payload dans une URL ne le déclencherait pas."
        )
        steps.append(
            f"COMMENT : connecte-toi avec un compte de test, ouvre {where}, "
            f"saisis le payload directement dans le champ '{param}', puis "
            "soumets le formulaire (bouton d'enregistrement/envoi)."
        )
        steps.append(
            "Reproduction technique équivalente (requête brute, ce que "
            f"DalFox a fait) : POST {url} avec le cookie de session et le "
            f"corps '{param}=<payload>'."
        )
    elif test_url:
        hint = _UI_HINTS.get(param)
        steps.append(
            f"OÙ : la barre d'adresse du navigateur (paramètre d'URL '{param}')."
        )
        steps.append(f"COMMENT : coller cette URL et appuyer sur Entrée → {test_url}")
        if hint:
            steps.append(
                f"Astuce UI : ce paramètre correspond généralement à {hint} — "
                "tu peux aussi taper le payload directement là plutôt que "
                "de modifier l'URL à la main."
            )
    else:
        steps.append(
            "Reproduction manuelle impossible automatiquement (paramètre ou "
            "URL manquant) — utiliser le payload et le contexte ci-dessus "
            "pour tester à la main."
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
            "Vérification automatique par navigateur non applicable : ce "
            "payload cible un champ de formulaire POST authentifié, pas un "
            "paramètre d'URL. Le signal de confiance vient du fuzzing "
            "authentifié effectué par DalFox (voir étapes de reproduction)."
        )
        vuln["reproduction_steps"] = _build_reproduction_steps(vuln, None)
        return

    test_url = _inject_payload_into_url(
        vuln.get("url", ""), vuln.get("parameter", ""), vuln.get("payload", "")
    )
    vuln["reproduction_url"] = test_url or ""

    if not test_url:
        vuln["verification_note"] = (
            "Vérification impossible : paramètre ou URL manquant."
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
                shot = await _snap(page, "Avant injection (page originale)")
                if shot:
                    screenshots.append(shot)
            except Exception:
                pass  # best-effort : l'échec du "avant" ne bloque pas la vérification

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
        if dialog_fired:
            await _annotate_confirmed(page)
        result_shot = await _snap(
            page,
            "Résultat (payload exécuté — bandeau ajouté par l'outil)" if dialog_fired
            else "Résultat (après injection, aucune exécution)",
        )
        if result_shot:
            screenshots.append(result_shot)
        vuln["screenshots"] = screenshots
        vuln["screenshot_b64"] = screenshots[-1]["image_b64"] if screenshots else ""
    except Exception as exc:
        logger.debug("Vérification impossible pour %s : %s", test_url, exc)
        vuln["verification_note"] = f"Vérification impossible : {exc}"
        vuln["screenshots"] = screenshots
    finally:
        await context.close()
        steps = _build_reproduction_steps(vuln, test_url)
        if vuln.get("verification_note"):
            steps.append(f"Résultat observé : {vuln['verification_note']}")
        vuln["reproduction_steps"] = steps


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
