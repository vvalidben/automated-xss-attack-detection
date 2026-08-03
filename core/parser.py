"""
parser.py  (core/parser.py)
===========================
Normalisation des sorties brutes des scanners en une liste homogène de
`Vulnerability`. On unifie XSStrike (texte) et DalFox (JSON) dans un même
schéma, on déduplique, et on attribue une sévérité.

BeautifulSoup / LXML sont utilisés pour l'analyse fine du HTML lorsque c'est
pertinent (ex : re-inspection d'un contexte d'injection), et LXML sert de
parseur rapide par défaut.

Sortie : liste de dictionnaires prêts à être injectés dans le rapport.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any

from bs4 import BeautifulSoup

logger = logging.getLogger("parser")


# --------------------------------------------------------------------------
# Modèle unifié de vulnérabilité
# --------------------------------------------------------------------------
@dataclass
class Vulnerability:
    tool: str                          # scanner d'origine
    type: str = "XSS"                  # Reflected / DOM / Stored / XSS
    severity: str = "Medium"           # Critical / High / Medium / Low / Info
    url: str = ""
    parameter: str = ""                # paramètre vulnérable si connu
    payload: str = ""                  # payload ayant déclenché la détection
    context: str = ""                  # emplacement où le payload a atterri
    evidence: str = ""                 # preuve / contexte
    confidence: str = "unknown"        # high / medium / low
    cwe: str = "CWE-79"                # Cross-Site Scripting
    method: str = "GET"                # méthode HTTP réellement testée (GET | POST)
    source_page: str = ""              # page où le formulaire POST a été découvert (si POST)
    source: str = ""                   # OÙ la donnée attaquant-contrôlée entre (taint source)
    sink: str = ""                     # OÙ elle est utilisée dangereusement (taint sink)
    raw: dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> tuple:
        return (self.url, self.parameter, self.payload[:80], self.type)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Parsing DalFox (sortie JSON / JSON-lines)
# --------------------------------------------------------------------------
def _parse_dalfox(raw: str, target: str) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    raw = (raw or "").strip()
    if not raw:
        return vulns

    entries: list[dict] = []

    # DalFox --format json peut sortir soit un tableau JSON, soit du JSON-lines.
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            entries = parsed
        elif isinstance(parsed, dict):
            entries = [parsed]
    except json.JSONDecodeError:
        # Repli JSON-lines : une entrée JSON par ligne.
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for e in entries:
        # DalFox utilise des clés comme: type, severity, param, payload, data, message_str
        payload = e.get("payload", "") or e.get("inject_type", "")
        parameter = e.get("param", "")
        evidence = e.get("message_str") or e.get("cwe", "") or e.get("type", "")

        # Sans payload NI paramètre NI preuve exploitable, l'entrée n'est pas
        # une vulnérabilité confirmée (souvent des messages BAV/informatifs) :
        # on l'ignore pour ne pas gonfler artificiellement le rapport.
        if not payload and not parameter and not evidence:
            continue

        sev = (e.get("severity") or "medium").capitalize()
        sink_desc = _describe_inject_type(e.get("inject_type", ""))
        vulns.append(
            Vulnerability(
                tool="dalfox",
                type=_map_type(e.get("type", "")),
                severity=_normalize_severity(sev),
                url=e.get("data") or e.get("evidence") or target,
                parameter=parameter,
                payload=payload,
                context=sink_desc,
                evidence=evidence,
                confidence="high" if e.get("type", "").upper() in ("V", "VERIFY") else "medium",
                # `source`/`sink` : le paramètre reste provisoire ici (GET par
                # défaut) — `parse_scan_results` le corrige en "POST" quand la
                # découverte vient de run_dalfox_authenticated_post().
                source=f"Parameter '{parameter}' (GET)" if parameter else "Parameter not identified",
                sink=sink_desc or "Sink not specified by DalFox",
                raw=e,
            )
        )
    return vulns


def _describe_inject_type(code: str) -> str:
    """
    Traduit le `inject_type` de DalFox (ex: "inHTML-URL", "inJS", "inATTR")
    en description lisible de l'endroit où le payload a atterri.
    """
    if not code:
        return ""
    low = code.lower()
    if low.startswith("injs"):
        base = "JavaScript block / event handler"
    elif low.startswith("inhtml"):
        base = "HTML body"
    elif low.startswith("inattr"):
        base = "HTML attribute"
    else:
        base = "Unknown context"
    return f"{base} ({code})"


# --------------------------------------------------------------------------
# Parsing XSStrike (sortie texte colorée)
# --------------------------------------------------------------------------
# XSStrike écrit des lignes du type :
#   [+] Payload: <svg/onload=...>
#   [+] Efficiency: 100
#   [+] Confidence: 10
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_PAYLOAD_RE = re.compile(r"payload\s*[:>]\s*(.+)", re.IGNORECASE)
_EFFICIENCY_RE = re.compile(r"efficiency\s*[:>]\s*(\d+)", re.IGNORECASE)
_CONFIDENCE_RE = re.compile(r"confidence\s*[:>]\s*(\d+)", re.IGNORECASE)
_PARAM_RE = re.compile(r"(?:testing\s+)?parameter\s*[:>]\s*(\S+)", re.IGNORECASE)


def _parse_xsstrike(raw: str, target: str) -> list[Vulnerability]:
    """
    NOTE : seules les lignes "Payload:" explicites sont considérées comme des
    findings. Une première version acceptait aussi toute ligne contenant des
    mots-clés comme "reflection"/"vulnerable" en secours, mais XSStrike émet
    aussi ces mots dans des lignes purement informatives ("[-] No reflection
    found", "[!] Reflections found: 2", "WAF Status: ..."), ce qui créait des
    faux positifs. On ne fait donc confiance qu'au format structuré.
    """
    vulns: list[Vulnerability] = []
    raw = _ANSI_RE.sub("", raw or "")
    if not raw.strip():
        return vulns

    current: dict[str, Any] = {}
    # Le paramètre testé est annoncé une seule fois ("Testing parameter: q")
    # avant que le fuzzer n'enchaîne des centaines de "Payload:" sans jamais
    # le répéter : on le garde à part pour qu'il survive aux flush().
    active_parameter = ""

    def flush() -> None:
        if not current.get("payload"):
            return
        eff = int(current.get("efficiency", 0))
        conf = int(current.get("confidence", 0))
        severity = "High" if eff >= 90 else "Medium" if eff >= 50 else "Low"
        param = active_parameter
        vulns.append(
            Vulnerability(
                tool="xsstrike",
                type="Reflected XSS",
                severity=severity,
                url=target,
                parameter=param,
                payload=current.get("payload", ""),
                context=(
                    f"URL query parameter '{param}'"
                    if param else "URL query parameter"
                ),
                evidence=f"Efficiency={eff}%, Confidence={conf}/10",
                confidence="high" if conf >= 8 else "medium" if conf >= 4 else "low",
                source=(
                    f"URL parameter '{param}' (GET)" if param
                    else "URL query parameter (GET)"
                ),
                sink="HTTP response body (unescaped HTML reflection)",
                raw=dict(current),
            )
        )
        current.clear()

    for line in raw.splitlines():
        stripped = line.strip()

        # "[-] No reflection found" etc. : jamais des findings, uniquement
        # du texte de statut négatif. (Les lignes "[!] Efficiency: ..." /
        # "[!] Confidence: ..." doivent, elles, continuer à être traitées
        # plus bas — ne pas les filtrer ici.)
        if stripped.startswith("[-]"):
            continue

        m = _PAYLOAD_RE.search(line)
        if m:
            # nouveau bloc de finding -> on flush le précédent
            flush()
            current["payload"] = html.unescape(m.group(1).strip())
            continue

        m = _EFFICIENCY_RE.search(line)
        if m:
            current["efficiency"] = m.group(1)
            continue

        m = _CONFIDENCE_RE.search(line)
        if m:
            current["confidence"] = m.group(1)
            continue

        m = _PARAM_RE.search(line)
        if m:
            active_parameter = m.group(1)
            continue

    flush()

    # Le moteur de fuzzing de XSStrike (recherche de contournement de WAF)
    # peut essayer plusieurs centaines de variantes du même payload sur le
    # même paramètre, chacune loggée avec sa propre ligne "Payload:". Ce
    # n'est PAS autant de vulnérabilités distinctes : on ne garde que la
    # meilleure tentative (efficacité puis confiance) par paramètre testé.
    best_by_param: dict[str, Vulnerability] = {}
    for v in vulns:
        key = v.parameter or "?"
        existing = best_by_param.get(key)
        if existing is None:
            best_by_param[key] = v
            continue
        eff = int(v.raw.get("efficiency", 0))
        existing_eff = int(existing.raw.get("efficiency", 0))
        if (eff, int(v.raw.get("confidence", 0))) > (
            existing_eff, int(existing.raw.get("confidence", 0))
        ):
            best_by_param[key] = v
    return list(best_by_param.values())


# --------------------------------------------------------------------------
# Helpers de normalisation
# --------------------------------------------------------------------------
def _normalize_severity(sev: str) -> str:
    sev = (sev or "").strip().capitalize()
    mapping = {
        "Critical": "Critical", "High": "High", "Medium": "Medium",
        "Low": "Low", "Info": "Info", "Information": "Info",
        "Informational": "Info", "": "Medium",
    }
    return mapping.get(sev, "Medium")


def _map_type(t: str) -> str:
    t = (t or "").lower()
    if "dom" in t:
        return "DOM XSS"
    if "stored" in t:
        return "Stored XSS"
    if "reflect" in t or t in ("v", "verify", "g", "grep"):
        return "Reflected XSS"
    return "XSS"


# --------------------------------------------------------------------------
# Analyse DOM optionnelle (BeautifulSoup / LXML)
# --------------------------------------------------------------------------
def analyze_html_context(html_content: str, needle: str) -> str:
    """
    Utilise BeautifulSoup (parseur lxml) pour déterminer le contexte dans lequel
    une valeur `needle` est réfléchie (attribut, texte, script...). Sert à
    enrichir la preuve d'une vulnérabilité. Robuste aux HTML malformés.
    """
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception:
        return "context undetermined"

    for tag in soup.find_all(True):
        if tag.string and needle in tag.string:
            return f"reflected in <{tag.name}> (text content)"
        for attr, val in tag.attrs.items():
            if isinstance(val, str) and needle in val:
                return f"reflected in the '{attr}' attribute of <{tag.name}>"
    return "reflected in the HTML (context not identified)"


# --------------------------------------------------------------------------
# Point d'entrée principal
# --------------------------------------------------------------------------
def parse_scan_results(scan_results: list) -> list[dict[str, Any]]:
    """
    Reçoit une liste de `ScanResult` (voir scanner_manager.py) et renvoie la
    liste dédupliquée des vulnérabilités normalisées (en dicts).
    """
    all_vulns: list[Vulnerability] = []

    for res in scan_results:
        # `res` est un ScanResult ; on accède aux attributs de façon défensive.
        tool = getattr(res, "tool", "unknown")
        target = getattr(res, "target", "")
        raw = getattr(res, "raw_output", "") or ""
        error = getattr(res, "error", None)

        if error:
            logger.warning("[%s] scan en erreur : %s", tool, error)
            continue

        try:
            if tool == "dalfox":
                new_vulns = _parse_dalfox(raw, target)
            elif tool == "xsstrike":
                new_vulns = _parse_xsstrike(raw, target)
            else:
                logger.debug("Outil inconnu, ignoré : %s", tool)
                new_vulns = []
            # La méthode HTTP réellement testée (GET par défaut, POST pour le
            # DalFox authentifié) vient du ScanResult, pas de la sortie brute
            # du scanner : on la reporte ici pour que le rapport sache si le
            # payload s'envoie via une URL ou via un corps de formulaire.
            method = getattr(res, "method", "GET")
            source_page = getattr(res, "source_page", "")
            for v in new_vulns:
                v.method = method
                v.source_page = source_page
                if method == "POST":
                    where = source_page or v.url
                    v.source = f"Form field '{v.parameter}' (POST, {where})"
            all_vulns.extend(new_vulns)
        except Exception as exc:  # robustesse : un parseur ne doit pas tout casser
            logger.error("Échec du parsing pour %s : %s", tool, exc)

    # Déduplication.
    seen: set[tuple] = set()
    unique: list[Vulnerability] = []
    for v in all_vulns:
        key = v.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(v)

    # Tri par sévérité (Critical d'abord).
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique.sort(key=lambda v: order.get(v.severity, 5))

    logger.info("Parsing terminé : %d vulnérabilités uniques", len(unique))
    return [v.to_dict() for v in unique]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # Petit test unitaire local du parseur DalFox.
    sample = '[{"type":"V","severity":"high","param":"q","payload":"<script>alert(1)</script>","data":"http://localhost:3000/?q=x","message_str":"reflected"}]'

    class _Fake:
        tool = "dalfox"
        target = "http://localhost:3000"
        raw_output = sample
        error = None

    print(json.dumps(parse_scan_results([_Fake()]), indent=2, ensure_ascii=False))
