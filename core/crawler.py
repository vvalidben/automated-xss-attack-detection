"""
crawler.py  (core/crawler.py)
=============================
Crawler JS-aware basé sur **Playwright**.

Rôle dans le pipeline :
    1. Ouvrir la cible dans un navigateur Chromium headless (rendu réel du JS,
       indispensable pour les SPA type OWASP Juice Shop / Angular).
    2. Découvrir récursivement les URLs internes (liens <a>, navigations JS).
    3. Extraire les formulaires et leurs champs (points d'injection potentiels).
    4. Détecter des indices de **sinks DOM-XSS** (innerHTML, document.write,
       eval, location.hash, etc.) présents dans le HTML/JS rendu.
    5. Sonder activement le DOM-XSS côté client (voir _probe_dom_xss) : sur
       une SPA, XSStrike/DalFox ne voient que la réponse HTTP brute et ratent
       les vulnérabilités où le framework (Angular/React) injecte lui-même
       le payload dans le DOM sans échappement. Le crawler teste directement
       dans le navigateur et ne retient une trouvaille que si un dialogue JS
       s'est réellement déclenché (preuve d'exécution, pas une heuristique).

Le crawler cartographie la surface d'attaque pour les scanners DAST
(XSStrike / DalFox), ET confirme lui-même les DOM-XSS qu'eux seuls ne
peuvent pas détecter depuis l'extérieur du navigateur.

Sortie : un objet `CrawlResult` sérialisable (dataclass -> dict).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any
from urllib.parse import urljoin, urlparse, urldefrag, quote

from playwright.async_api import async_playwright, Page, TimeoutError as PWTimeout

import config

logger = logging.getLogger("crawler")


# --------------------------------------------------------------------------
# Modèles de données
# --------------------------------------------------------------------------
@dataclass
class FormField:
    name: str
    type: str = "text"


@dataclass
class DiscoveredForm:
    """Un formulaire HTML découvert = point d'injection candidat."""
    action: str                       # URL cible du formulaire (absolue)
    method: str = "get"               # get / post
    fields: list[FormField] = field(default_factory=list)
    source_page: str = ""             # page où le formulaire a été trouvé


@dataclass
class DomSink:
    """Indice de sink DOM-XSS repéré dans le HTML/JS rendu."""
    page: str
    pattern: str                      # ex : "innerHTML", "document.write"
    snippet: str                      # extrait de code autour du match


@dataclass
class CrawlResult:
    target: str
    urls: list[str] = field(default_factory=list)          # pages découvertes
    injectable_urls: list[str] = field(default_factory=list)  # URLs avec params
    forms: list[DiscoveredForm] = field(default_factory=list)
    dom_sinks: list[DomSink] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Vulnérabilités DOM-XSS confirmées PAR EXÉCUTION RÉELLE pendant le crawl
    # (voir _probe_dom_xss) : ce ne sont pas des candidats à re-tester, mais
    # déjà des preuves (payload exécuté + capture d'écran).
    dom_xss_findings: list[dict[str, Any]] = field(default_factory=list)
    # Jeton de session du compte jetable créé par _register_and_login(), si
    # l'authentification a réussi. Permet à scanner_manager.py de lancer des
    # scans DAST authentifiés (ex : DalFox en POST sur un formulaire qui
    # exige une session) sur des pages sinon inaccessibles anonymement.
    auth_token: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Motifs de détection de sinks DOM-XSS (heuristique, non exhaustive)
# --------------------------------------------------------------------------
DOM_SINK_PATTERNS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"\.insertAdjacentHTML\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"location\.hash",
    r"location\.search",
    r"\$\(.*\)\.html\s*\(",          # jQuery .html()
]
_SINK_REGEX = re.compile("|".join(DOM_SINK_PATTERNS))


# --------------------------------------------------------------------------
# Bruit réseau à exclure des URLs "injectables" capturées passivement
# --------------------------------------------------------------------------
# Le protocole de handshake Socket.IO/Engine.IO régénère une URL différente
# (paramètre `t` = timestamp) à chaque poll, plusieurs fois par seconde tant
# que la page reste ouverte. Sans ce filtre, ce bruit noie les vraies URLs
# d'API (ex: /rest/products/search?q=...) dans la limite `max_urls`.
# "api/challenges" est un endpoint interne de suivi de progression (Juice
# Shop), pas une fonctionnalité utilisateur : le fuzzer avec des payloads
# XSS y provoque un crash mémoire (heap OOM) côté Node sans révéler de
# vulnérabilité exploitable côté client — on l'exclut donc du scan.
_NOISE_PATH_RE = re.compile(
    r"socket\.io|/__webpack|hot-update|api/challenges", re.IGNORECASE
)
_STATIC_EXT_RE = re.compile(
    r"\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|json)(\?|$)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------
# Sondage DOM-XSS actif
# --------------------------------------------------------------------------
# XSStrike/DalFox testent la réponse HTTP brute : sur une SPA Angular/React
# comme Juice Shop, le XSS réel se produit côté client (le JSON de l'API est
# injecté sans échappement dans le DOM par le framework), invisible dans la
# réponse HTTP elle-même. On teste donc directement dans un vrai navigateur
# avec une petite liste de payloads connus pour contourner l'assainissement
# Angular usuel, et on ne considère la vulnérabilité confirmée QUE si une
# boîte de dialogue JS (alert/confirm/prompt) se déclenche réellement.
DOM_XSS_PAYLOADS = [
    '<iframe src="javascript:alert(`xss-poc`)">',
    '<img src=x onerror=alert(`xss-poc`)>',
    '<svg onload=alert(`xss-poc`)>',
    # Payload spécifique attendu par le easter-egg "Bonus Payload" de Juice
    # Shop (défi xssBonusChallenge) : un embed vidéo précis, reconnu
    # côté serveur. Les payloads génériques ci-dessus ne le déclenchent pas.
    '<iframe width="100%" height="166" scrolling="no" frameborder="no" '
    'allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//'
    'api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&'
    'hide_related=false&show_comments=true&show_user=true&show_reposts=false&'
    'show_teaser=true"></iframe><script>alert(`xss-poc`)</script>',
]

# --------------------------------------------------------------------------
# Identifiants d'un compte jetable créé pour explorer les pages nécessitant
# une session (profil, feedback avec auteur pré-rempli, etc.).
# --------------------------------------------------------------------------
def _random_credentials() -> tuple[str, str]:
    import random
    import string

    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"scanner_{suffix}@example.test", f"Sc4nner!{suffix}"


# Résout une expression arithmétique simple ("7*3-4") comme celles utilisées
# par le CAPTCHA du formulaire de feedback, sans jamais appeler eval() sur du
# texte non maîtrisé (on n'autorise que chiffres/espaces/opérateurs de base).
_CAPTCHA_EXPR_RE = re.compile(r"what is\s*([\d\s+\-*/]+?)\s*\?", re.IGNORECASE)
_SAFE_ARITH_RE = re.compile(r"^[\d\s+\-*/]+$")


def _solve_captcha(text: str) -> str | None:
    m = _CAPTCHA_EXPR_RE.search(text)
    if not m:
        return None
    expr = m.group(1).strip()
    if not _SAFE_ARITH_RE.match(expr):
        return None
    try:
        import ast

        tree = ast.parse(expr, mode="eval")
        for node in ast.walk(tree):
            if not isinstance(
                node,
                (ast.Expression, ast.BinOp, ast.Add, ast.Sub, ast.Mult,
                 ast.Div, ast.Constant, ast.USub, ast.UAdd),
            ):
                return None
        return str(int(eval(compile(tree, "<captcha>", "eval"))))
    except Exception:
        return None


# --------------------------------------------------------------------------
# Crawler
# --------------------------------------------------------------------------
class PlaywrightCrawler:
    """
    Crawler asynchrone. Utilisation :

        result = await PlaywrightCrawler(target).run()
    """

    def __init__(
        self,
        target: str,
        max_pages: int | None = None,
        max_depth: int | None = None,
        headless: bool | None = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.max_pages = max_pages or config.CRAWLER_MAX_PAGES
        self.max_depth = max_depth or config.CRAWLER_MAX_DEPTH
        self.headless = config.CRAWLER_HEADLESS if headless is None else headless

        self.origin = self._origin(self.target)
        self.result = CrawlResult(target=self.target)
        self._visited: set[str] = set()
        self._seen_form_sigs: set[str] = set()
        # URLs d'API (XHR/fetch) capturées passivement pendant la navigation :
        # sur une SPA (Angular/React), les vrais points d'injection sont des
        # appels REST (ex: /rest/products/search?q=...), pas des <a href>.
        self._captured_api_urls: set[str] = set()
        # État du sondage DOM-XSS actif (voir _probe_dom_xss) : un budget
        # global d'essais pour couvrir plusieurs pages/champs sans spammer
        # la cible ni ralentir excessivement le crawl.
        self._dialog_fired = False
        self._dom_probe_budget = 15
        self._form_probe_budget = 10
        self._reflected_probe_budget = 8
        # Compte jetable créé via _register_and_login() : de nombreuses pages
        # (profil, feedback avec auteur pré-rempli, menu compte...) ne sont
        # accessibles/pertinentes qu'après authentification et sont sinon
        # invisibles au crawler.
        self._login_email, self._login_password = _random_credentials()
        self._logged_in = False
        self._finding_keys: set[tuple[str, str, str, str]] = set()

    async def _on_dialog(self, dialog) -> None:
        """Capture le déclenchement d'un dialogue JS (preuve d'exécution XSS)."""
        self._dialog_fired = True
        try:
            await dialog.dismiss()
        except Exception:
            pass

    # ---- Helpers -------------------------------------------------------
    @staticmethod
    def _origin(url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _same_origin(self, url: str) -> bool:
        return self._origin(url) == self.origin

    @staticmethod
    def _normalize(url: str) -> str:
        """
        Retire le fragment (#...) SAUF s'il s'agit d'une route Angular
        (ex: "#/login", "#/search?q=..."). Juice Shop (et la plupart des SPA
        Angular) utilise le hash comme routeur côté client : chaque page de
        l'appli vit derrière un fragment de la forme "#/route". Un simple
        `urldefrag()` les réduit TOUTES à l'URL de base ("http://host/"),
        déjà visitée -> elles ne sont jamais mises en file d'attente et
        l'essentiel du site (login, contact, profil, recherche...) reste
        invisible au crawler. On ne strip que les fragments qui ne
        ressemblent PAS à une route (ex: ancre "#top").
        """
        base, frag = urldefrag(url)
        if frag.startswith("/"):
            return f"{base}#{frag}"
        return base

    # ---- Extraction d'une page ----------------------------------------
    async def _extract_links(self, page: Page, base_url: str) -> list[str]:
        try:
            hrefs = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.getAttribute('href'))"
            )
        except Exception:
            hrefs = []

        links: list[str] = []
        for href in hrefs:
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            absolute = self._normalize(urljoin(base_url, href))
            if config.CRAWLER_SAME_ORIGIN_ONLY and not self._same_origin(absolute):
                continue
            if _NOISE_PATH_RE.search(urlparse(absolute).path):
                continue
            links.append(absolute)
        return links

    async def _extract_forms(self, page: Page, base_url: str) -> list[DiscoveredForm]:
        try:
            raw_forms = await page.evaluate(
                """() => Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.getAttribute('action') || '',
                        method: (f.getAttribute('method') || 'get').toLowerCase(),
                        fields: Array.from(
                            f.querySelectorAll('input, textarea, select')
                        ).map(i => ({
                            name: i.getAttribute('name') || i.getAttribute('formControlName')
                                  || i.getAttribute('id') || '',
                            type: i.getAttribute('type') || i.tagName.toLowerCase()
                        }))
                }))"""
            )
        except Exception as exc:  # pragma: no cover - robustesse
            logger.debug("Extraction des formulaires impossible sur %s : %s", base_url, exc)
            return []

        forms: list[DiscoveredForm] = []
        for rf in raw_forms:
            action = self._normalize(urljoin(base_url, rf.get("action") or base_url))
            fields = [
                FormField(name=f["name"], type=f.get("type", "text"))
                for f in rf.get("fields", [])
                if f.get("name")
            ]
            if not fields:
                continue
            # Signature pour dédupliquer les formulaires identiques.
            sig = f"{rf.get('method')}|{action}|{','.join(sorted(f.name for f in fields))}"
            if sig in self._seen_form_sigs:
                continue
            self._seen_form_sigs.add(sig)
            forms.append(
                DiscoveredForm(
                    action=action,
                    method=rf.get("method", "get"),
                    fields=fields,
                    source_page=base_url,
                )
            )
        return forms

    def _on_request(self, request) -> None:
        """
        Écouteur passif des requêtes réseau (XHR/fetch inclus).

        Sur une SPA, la recherche/les filtres passent par des appels GET vers
        une API REST (ex : /rest/products/search?q=xss) plutôt que par des
        liens <a href> classiques. On capture ces URLs paramétrées pour les
        proposer comme cibles aux scanners DAST.
        """
        try:
            if request.method != "GET":
                return
            url = request.url
            if not urlparse(url).query:
                return
            if config.CRAWLER_SAME_ORIGIN_ONLY and not self._same_origin(url):
                return
            path = urlparse(url).path
            if _NOISE_PATH_RE.search(path) or _STATIC_EXT_RE.search(path):
                return
            self._captured_api_urls.add(self._normalize(url))
        except Exception:
            pass

    async def _dismiss_overlays(self, page: Page) -> None:
        """
        Ferme les overlays modaux affichés au premier chargement (bannière de
        bienvenue Juice Shop, consentement cookies, etc.).

        Tant qu'un `cdk-overlay-backdrop` (Angular Material) est présent, TOUT
        clic ailleurs sur la page — y compris sur l'icône de recherche — est
        intercepté et échoue silencieusement. Sans ce nettoyage, la barre de
        recherche ne s'ouvre jamais et aucun payload ne peut y être testé.
        """
        selectors = (
            "button[aria-label='Close Welcome Banner']",
            "#welcomeBanner__close",
            ".cc-dismiss",
            "button[aria-label*='dismiss cookie' i]",
        )
        for sel in selectors:
            try:
                el = await page.query_selector(sel)
                if el:
                    await el.click(timeout=1000)
                    await page.wait_for_timeout(200)
            except Exception:
                continue

        # Filet de sécurité : tout backdrop restant se ferme généralement
        # avec Echap (comportement standard Angular Material CDK overlay).
        try:
            if await page.query_selector(".cdk-overlay-backdrop"):
                await page.keyboard.press("Escape")
                await page.wait_for_timeout(200)
        except Exception:
            pass

    async def _goto_resilient(self, page: Page, url: str) -> None:
        """`page.goto` avec repli domcontentloaded si networkidle expire
        (fréquent sur les SPA qui pollent en continu, ex : Socket.IO)."""
        try:
            await page.goto(url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS, wait_until="networkidle")
        except PWTimeout:
            await page.goto(url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS, wait_until="domcontentloaded")

    async def _register_and_login(self, page: Page) -> None:
        """
        Crée un compte jetable et se connecte AVANT le crawl BFS (jusqu'à 2
        tentatives, avec des identifiants regénérés à chaque essai pour
        éviter un conflit si la 1re tentative s'est arrêtée après
        l'inscription mais avant la connexion).

        Beaucoup de vulnérabilités XSS de Juice Shop (profil utilisateur,
        feedback avec auteur pré-rempli, menu compte étendu...) ne sont
        atteignables qu'après authentification : sans session, ces pages
        n'apparaissent jamais dans le graphe de liens exploré par le crawler.
        Best-effort : si le site cible n'a pas ce formulaire (sélecteurs
        introuvables), on abandonne et le crawl continue en mode anonyme.
        """
        for attempt in range(1, 3):
            self._login_email, self._login_password = _random_credentials()
            try:
                if await self._try_register_and_login(page):
                    return
                reason = "formulaire d'inscription/connexion non reconnu"
            except Exception as exc:
                reason = str(exc)
            logger.warning(
                "Login pré-crawl : échec à l'essai %d/2 (%s) — %s",
                attempt, reason, "nouvel essai" if attempt == 1 else "abandon, mode anonyme",
            )

    async def _try_register_and_login(self, page: Page) -> bool:
        """Une tentative d'inscription + connexion. Renvoie False si le site
        cible ne présente pas ce formulaire (pas une erreur, cible différente)."""
        await self._goto_resilient(page, f"{self.origin}/#/register")
        await page.wait_for_timeout(500)
        await self._dismiss_overlays(page)

        try:
            await page.wait_for_selector("#emailControl", timeout=6000)
        except PWTimeout:
            return False  # Pas de formulaire d'inscription reconnu -> abandon.

        await page.fill("#emailControl", self._login_email)
        await page.fill("#passwordControl", self._login_password)
        await page.fill("#repeatPasswordControl", self._login_password)
        try:
            await page.click("#mat-select-0", timeout=3000)
            await page.wait_for_timeout(200)
            await page.click("mat-option >> nth=0", timeout=3000)
        except Exception:
            pass
        security_answer = await page.query_selector("#securityAnswerControl")
        if security_answer:
            await page.fill("#securityAnswerControl", "scanner")
        await page.click("#registerButton", timeout=5000)
        await page.wait_for_timeout(1200)

        await self._goto_resilient(page, f"{self.origin}/#/login")
        await page.wait_for_timeout(500)
        await self._dismiss_overlays(page)
        try:
            await page.wait_for_selector("#email", timeout=6000)
        except PWTimeout:
            return False
        await page.fill("#email", self._login_email)
        await page.fill("#password", self._login_password)
        await page.click("#loginButton", timeout=5000)
        await page.wait_for_timeout(1200)

        # Le menu compte n'expose pas toujours un <a href> classique pour
        # le profil (navigation programmatique) : on ajoute son URL
        # directement comme point d'entrée supplémentaire du crawl.
        try:
            await page.wait_for_selector(
                "#navbarLogoutButton, button[aria-label='Show/hide account menu']",
                timeout=5000,
            )
        except PWTimeout:
            return False

        self._logged_in = True
        try:
            token = await page.evaluate("window.localStorage.getItem('token')")
            if token:
                self.result.auth_token = token
        except Exception:
            pass
        logger.info("Connecté avec le compte jetable %s", self._login_email)
        return True

    async def _trigger_search_inputs(self, page: Page) -> None:
        """
        Tente de révéler puis d'utiliser une barre de recherche.

        De nombreuses SPA (Juice Shop compris) cachent le champ de recherche
        derrière une icône, et l'appel API qui nous intéresse n'est déclenché
        qu'après une frappe utilisateur. On simule cette interaction pour
        provoquer l'appel réseau capturé par `_on_request`.
        """
        try:
            for sel in ("[aria-label*='search' i]", "button[mat-icon-button]"):
                try:
                    el = await page.query_selector(sel)
                    if el:
                        await el.click(timeout=1000)
                        await page.wait_for_timeout(300)
                except Exception:
                    continue

            inputs = await page.query_selector_all(
                "input[type='search'], input[type='text'], "
                "input[name*='search' i], input[id*='search' i]"
            )
            for inp in inputs[:3]:
                try:
                    await inp.fill("xsstrike")
                    await inp.press("Enter")
                    await page.wait_for_timeout(600)
                except Exception:
                    continue
        except Exception:
            pass

    async def _record_finding(
        self, page: Page, base_url: str, payload: str, parameter: str,
        vuln_type: str, note: str,
    ) -> None:
        """Factorise l'enregistrement d'une découverte XSS confirmée par exécution."""
        # Le même sondage (ex : recherche) s'exécute sur chaque page visitée
        # (barre de recherche présente partout) : sans dédoublonnage, une
        # unique vulnérabilité apparaîtrait une fois par page dans le
        # rapport. On ne garde qu'une occurrence par (type, url, paramètre,
        # payload) — contrairement à `parse_scan_results`, ce dédoublonnage
        # ne s'applique qu'aux découvertes du crawler, faites AVANT le
        # merge avec les résultats XSStrike/DalFox dans app.py.
        dedup_key = (vuln_type, base_url, parameter, payload)
        if dedup_key in self._finding_keys:
            return
        self._finding_keys.add(dedup_key)
        try:
            screenshot_bytes = await page.screenshot(full_page=False)
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
        except Exception:
            screenshot_b64 = ""
        self.result.dom_xss_findings.append({
            "tool": "playwright-dom-probe",
            "type": vuln_type,
            "severity": "Critical",
            "url": base_url,
            "parameter": parameter,
            "payload": payload,
            "context": "DOM — rendu côté client (SPA)",
            "evidence": "Boîte de dialogue JS déclenchée dans un vrai navigateur",
            "confidence": "high",
            "cwe": "CWE-79",
            "confirmed": True,
            "screenshot_b64": screenshot_b64,
            "verification_note": note,
        })

    async def _probe_dom_xss(self, page: Page, base_url: str) -> None:
        """
        Teste activement les champs texte/recherche visibles avec une petite
        liste de payloads XSS connus, directement dans un vrai navigateur.

        Contrairement à XSStrike/DalFox (qui analysent la réponse HTTP brute),
        ceci détecte le XSS **côté client** propre aux SPA (Angular/React) :
        la vulnérabilité n'est retenue que si un dialogue JS (alert/confirm/
        prompt) se déclenche réellement — preuve d'exécution, pas heuristique.
        Un budget global (`_dom_probe_budget`) limite le nombre d'essais sur
        l'ensemble du crawl pour rester rapide et ne pas solliciter
        excessivement la cible.
        """
        if self._dom_probe_budget <= 0:
            return
        try:
            inputs = await page.query_selector_all(
                "input[type='search'], input[type='text'], textarea, "
                "input[name*='search' i], input[id*='search' i]"
            )
        except Exception:
            return

        for inp in inputs[:2]:
            if self._dom_probe_budget <= 0:
                break
            for payload in DOM_XSS_PAYLOADS:
                if self._dom_probe_budget <= 0:
                    break
                self._dom_probe_budget -= 1
                self._dialog_fired = False
                try:
                    await inp.fill(payload)
                    await inp.press("Enter")
                    await page.wait_for_timeout(1000)
                except Exception:
                    continue

                if self._dialog_fired:
                    await self._record_finding(
                        page, base_url, payload, "champ de recherche / texte",
                        "DOM XSS",
                        "Payload injecté directement dans le champ de saisie et "
                        "exécuté par le rendu JS de la page (alert() déclenché).",
                    )
                    # Un payload confirmé suffit pour ce champ : inutile de
                    # continuer à spammer la cible avec les autres payloads.
                    break

    async def _probe_reflected_xss(self, page: Page, base_url: str) -> None:
        """
        Teste le XSS réfléchi via injection DIRECTE dans l'URL (paramètre de
        requête), par opposition à `_probe_dom_xss` qui simule une frappe
        utilisateur dans un champ.

        Sur Juice Shop, le défi "Reflected XSS" exige précisément ce vecteur :
        naviguer vers une URL contenant le payload dans `?q=...` (le rendu
        Angular de la page de recherche l'injecte alors sans échappement).
        XSStrike/DalFox ne peuvent pas le trouver seuls ici car l'endpoint
        JSON qu'ils testent (`/rest/products/search?q=`) est correctement
        échappé — seule la route Angular qui consomme ce JSON est vulnérable,
        ce qui n'est visible qu'en rendant réellement la page.
        """
        if self._reflected_probe_budget <= 0:
            return
        try:
            has_search = await page.query_selector(
                "input[type='search'], input[type='text'], "
                "input[name*='search' i], input[id*='search' i]"
            )
        except Exception:
            has_search = None
        if not has_search:
            return

        # `page` est l'unique onglet partagé par toute la boucle BFS : le
        # laisser sur `test_url` après ce sondage ferait extraire à tort les
        # formulaires/liens de la page RÉFLÉCHIE (payload injecté) sous
        # l'étiquette de `base_url` dans les étapes suivantes du crawl. On
        # restaure systématiquement la page d'origine avant de rendre la
        # main, succès ou non.
        try:
            for payload in DOM_XSS_PAYLOADS[:3]:
                if self._reflected_probe_budget <= 0:
                    break
                self._reflected_probe_budget -= 1
                self._dialog_fired = False
                test_url = f"{self.origin}/#/search?q={quote(payload)}"
                try:
                    await page.goto(
                        test_url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                    await page.wait_for_timeout(1200)
                except Exception:
                    continue

                if self._dialog_fired:
                    await self._record_finding(
                        page, test_url, payload, "q (paramètre d'URL)",
                        "Reflected XSS",
                        "Payload placé directement dans le paramètre d'URL 'q' "
                        "(sans passer par le champ de saisie) et exécuté par le "
                        "rendu JS de la route Angular au chargement de la page.",
                    )
                    break
        finally:
            if page.url != base_url:
                await self._goto_resilient(page, base_url)
                await page.wait_for_timeout(300)

    async def _probe_persisted_forms(self, page: Page, base_url: str) -> None:
        """
        Teste le XSS persisté (stocké) via les formulaires non-recherche de
        la page (profil utilisateur, feedback...) : remplit les champs
        texte, soumet, puis recharge la page pour vérifier si la valeur
        stockée est réinjectée sans échappement.

        `_probe_dom_xss` ne couvre que les champs texte/recherche testés en
        place ; il ne soumet jamais rien, donc il ne peut pas voir un XSS qui
        n'apparaît qu'après un aller-retour serveur (valeur relue depuis la
        base). C'est pourtant le vecteur des défis "Persisted XSS" de Juice
        Shop (nom d'utilisateur, commentaire de feedback).
        """
        if self._form_probe_budget <= 0:
            return
        try:
            fields = await page.query_selector_all(
                "input[type='text']:not([id*='search' i]):not([name*='search' i]), "
                "input:not([type]):not([id*='search' i]), textarea"
            )
        except Exception:
            return
        if not fields:
            return

        # Résout le CAPTCHA du formulaire de feedback si présent (défi
        # persistedXssFeedbackChallenge) — sans quoi la soumission échoue
        # silencieusement et le champ "comment" n'est jamais persisté.
        captcha_input = await page.query_selector("#captchaControl")
        if captcha_input:
            try:
                body_text = await page.evaluate("document.body.innerText")
                answer = _solve_captcha(body_text)
                if answer is not None:
                    await captcha_input.fill(answer)
            except Exception:
                pass

        # Idem pour un éventuel slider de note requis (ex : formulaire de
        # feedback) : sans valeur, le formulaire reste invalide et le bouton
        # de soumission désactivé.
        try:
            slider = await page.query_selector("mat-slider, input[type='range']")
            if slider:
                await slider.click(timeout=1000)
                await page.keyboard.press("End")
                await page.wait_for_timeout(150)
        except Exception:
            pass

        payload = DOM_XSS_PAYLOADS[0]
        tested_any = False
        for field in fields[:3]:
            if self._form_probe_budget <= 0:
                break
            try:
                if not await field.is_visible() or not await field.is_enabled():
                    continue
                field_type = (await field.get_attribute("type")) or ""
                if field_type in ("email", "password", "hidden", "file", "checkbox", "radio"):
                    continue
            except Exception:
                continue
            self._form_probe_budget -= 1
            tested_any = True
            try:
                await field.fill(payload)
            except Exception:
                continue

        if not tested_any:
            return

        self._dialog_fired = False
        submitted = False
        for sel in (
            "button[type='submit']", "#submitButton", "#submit",
            "button[aria-label*='save' i]", "button[aria-label*='send' i]",
        ):
            try:
                btn = await page.query_selector(sel)
                if btn and await btn.is_visible():
                    await btn.click(timeout=1500)
                    submitted = True
                    break
            except Exception:
                continue
        if not submitted:
            return
        await page.wait_for_timeout(1000)

        # La soumission peut avoir navigué `page` ailleurs qu'sur `base_url`
        # (formulaire "legacy" en POST HTML classique, ex : /profile). Comme
        # pour `_probe_reflected_xss`, on restaure systématiquement l'onglet
        # partagé sur `base_url` avant de rendre la main au crawl BFS, pour
        # ne pas fausser l'extraction de formulaires/liens de l'étape
        # suivante.
        try:
            if self._dialog_fired:
                await self._record_finding(
                    page, base_url, payload, "champ de formulaire (persisté)",
                    "Persisted XSS",
                    "Payload soumis via un formulaire et exécuté immédiatement "
                    "après enregistrement (rendu non échappé de la valeur).",
                )
                return

            # Le rendu non échappé peut n'apparaître qu'après relecture
            # depuis le serveur (ex : nom d'utilisateur affiché ailleurs
            # après reload).
            try:
                await self._goto_resilient(page, base_url)
                self._dialog_fired = False
                await page.wait_for_timeout(1500)
            except Exception:
                return

            if self._dialog_fired:
                await self._record_finding(
                    page, base_url, payload, "champ de formulaire (persisté)",
                    "Persisted XSS",
                    "Payload soumis via un formulaire ; l'exécution ne s'est "
                    "déclenchée qu'après rechargement de la page (valeur relue "
                    "stockée côté serveur, rendue sans échappement).",
                )
        finally:
            if page.url != base_url:
                try:
                    await self._goto_resilient(page, base_url)
                    await page.wait_for_timeout(300)
                except Exception:
                    pass

    async def _detect_dom_sinks(self, page: Page, base_url: str) -> list[DomSink]:
        """Analyse le HTML rendu + les scripts inline pour repérer des sinks."""
        try:
            content = await page.content()
        except Exception:
            return []

        sinks: list[DomSink] = []
        for match in _SINK_REGEX.finditer(content):
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            snippet = content[start:end].replace("\n", " ").strip()
            sinks.append(
                DomSink(page=base_url, pattern=match.group(0), snippet=snippet)
            )
        return sinks

    # ---- Boucle principale --------------------------------------------
    async def run(self) -> CrawlResult:
        """Lance le crawl et renvoie le CrawlResult agrégé."""
        logger.info("Démarrage du crawl sur %s (max_pages=%s, depth=%s)",
                    self.target, self.max_pages, self.max_depth)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            context = await browser.new_context(ignore_https_errors=True)
            context.on("request", self._on_request)
            page = await context.new_page()
            page.on("dialog", lambda d: asyncio.ensure_future(self._on_dialog(d)))

            # Authentification AVANT le crawl BFS : sans session, tout un pan
            # du site (profil, feedback avec auteur, menu compte étendu...)
            # reste invisible au crawler (voir _register_and_login).
            await self._register_and_login(page)

            # File d'attente BFS : (url, profondeur)
            queue: list[tuple[str, int]] = [(self.target, 0)]
            if self._logged_in:
                # Le profil n'est accessible que par un clic JS programmatique
                # (pas de <a href>) : on l'ajoute explicitement comme point
                # d'entrée puisque le crawl par liens ne peut pas le trouver.
                queue.append((f"{self.origin}/profile", 0))

            try:
                while queue and len(self._visited) < self.max_pages:
                    url, depth = queue.pop(0)
                    url = self._normalize(url)
                    if url in self._visited or depth > self.max_depth:
                        continue
                    self._visited.add(url)

                    try:
                        await page.goto(
                            url,
                            timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                            wait_until="networkidle",
                        )
                    except PWTimeout:
                        # networkidle échoue souvent sur les SPA : on retente en
                        # se contentant du chargement du DOM.
                        try:
                            await page.goto(
                                url,
                                timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                                wait_until="domcontentloaded",
                            )
                        except Exception as exc:
                            self.result.errors.append(f"{url} : timeout ({exc})")
                            continue
                    except Exception as exc:
                        self.result.errors.append(f"{url} : {exc}")
                        continue

                    # Laisser le JS s'exécuter un court instant (rendu SPA).
                    await page.wait_for_timeout(600)

                    # Ferme bannière de bienvenue / cookies AVANT toute
                    # interaction : sinon leur backdrop intercepte tous les
                    # clics (voir _dismiss_overlays).
                    await self._dismiss_overlays(page)

                    # Déclenche une éventuelle recherche pour capturer l'appel
                    # API sous-jacent (voir _on_request).
                    await self._trigger_search_inputs(page)

                    # Sondage DOM-XSS actif : détecte le XSS côté client que
                    # XSStrike/DalFox ne peuvent pas voir (voir _probe_dom_xss).
                    await self._probe_dom_xss(page, url)

                    # Sondage XSS réfléchi via injection directe dans l'URL
                    # (vecteur distinct de _probe_dom_xss, voir docstring).
                    await self._probe_reflected_xss(page, url)

                    # Sondage XSS persisté via les formulaires de la page
                    # (profil, feedback...) : remplit + soumet + revérifie.
                    await self._probe_persisted_forms(page, url)

                    self.result.urls.append(url)
                    if urlparse(url).query:
                        self.result.injectable_urls.append(url)

                    # Formulaires + sinks
                    self.result.forms.extend(await self._extract_forms(page, url))
                    self.result.dom_sinks.extend(await self._detect_dom_sinks(page, url))

                    # Nouveaux liens à explorer
                    for link in await self._extract_links(page, url):
                        if link not in self._visited:
                            queue.append((link, depth + 1))

            finally:
                await context.close()
                await browser.close()

        # Fusion des URLs d'API capturées passivement (XHR/fetch) avec celles
        # trouvées via <a href> — ce sont souvent les seules réellement
        # injectables sur une SPA.
        self.result.injectable_urls.extend(self._captured_api_urls)

        # Dédoublonnage final
        self.result.urls = sorted(set(self.result.urls))
        self.result.injectable_urls = sorted(set(self.result.injectable_urls))

        logger.info(
            "Crawl terminé : %d pages, %d URLs injectables, %d formulaires, "
            "%d sinks DOM, %d DOM-XSS confirmés",
            len(self.result.urls),
            len(self.result.injectable_urls),
            len(self.result.forms),
            len(self.result.dom_sinks),
            len(self.result.dom_xss_findings),
        )
        return self.result


# --------------------------------------------------------------------------
# API synchrone pratique (pour appel depuis du code non-async)
# --------------------------------------------------------------------------
def crawl(target: str, **kwargs: Any) -> CrawlResult:
    """Wrapper synchrone : `crawl("http://localhost:3000")`."""
    return asyncio.run(PlaywrightCrawler(target, **kwargs).run())


# --------------------------------------------------------------------------
# Exécution directe (debug) — lancer depuis la racine : python -m core.crawler
# --------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import json
    import sys

    tgt = sys.argv[1] if len(sys.argv) > 1 else config.DEFAULT_TARGET
    res = crawl(tgt)
    print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
