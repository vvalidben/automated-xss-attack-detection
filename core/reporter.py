"""
reporter.py  (core/reporter.py)
===============================
Génération des rapports d'analyse :

    * HTML interactif via **Jinja2** (report_template.html),
    * PDF professionnel via **ReportLab** (métriques, camembert de sévérité,
      tableau détaillé des vulnérabilités).

Le reporter reçoit un `dict` de contexte agrégé (cible, stats crawler,
vulnérabilités normalisées) et produit deux fichiers horodatés dans REPORTS_DIR.
"""

from __future__ import annotations

import base64
import datetime as _dt
import io
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

import config

logger = logging.getLogger("reporter")


# --------------------------------------------------------------------------
# Construction du contexte de rapport
# --------------------------------------------------------------------------
def build_context(
    target: str,
    crawl_summary: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    scan_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Agrège toutes les données nécessaires au rendu (HTML et PDF)."""
    sev_counts = Counter(v.get("severity", "Medium") for v in vulnerabilities)
    # On garantit l'ordre canonique des sévérités.
    severity_stats = {s: sev_counts.get(s, 0) for s in config.SEVERITY_ORDER}

    # Le score/niveau de risque affiché en tête de rapport ne doit PAS être
    # gonflé par un simple score heuristique de scanner (XSStrike/DalFox
    # sans preuve d'exécution) : XSStrike en particulier note par similarité
    # de chaîne face à un WAF et produit régulièrement des faux positifs
    # (payload présent dans la réponse, jamais réellement exécuté). On base
    # donc le risque affiché sur les vulnérabilités CONFIRMÉES (dialogue JS
    # déclenché dans un vrai navigateur, voir verifier.py) ; les non
    # confirmées restent visibles dans le détail mais avec un badge
    # "possible faux positif" et sans peser sur le score.
    confirmed = [v for v in vulnerabilities if v.get("confirmed")]
    unconfirmed_count = len(vulnerabilities) - len(confirmed)
    confirmed_sev_counts = Counter(v.get("severity", "Medium") for v in confirmed)
    confirmed_severity_stats = {s: confirmed_sev_counts.get(s, 0) for s in config.SEVERITY_ORDER}

    # Score de risque simple pondéré.
    weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
    risk_score = sum(weights[s] * c for s, c in confirmed_severity_stats.items())

    if confirmed_severity_stats["Critical"] or confirmed_severity_stats["High"]:
        risk_level = "High"
    elif confirmed_severity_stats["Medium"]:
        risk_level = "Moderate"
    elif confirmed:
        risk_level = "Low"
    elif vulnerabilities:
        # Rien de confirmé : uniquement des signaux heuristiques non vérifiés.
        risk_level = "Unconfirmed (possible false positives)"
    else:
        risk_level = "No XSS risk detected"

    return {
        "target": target,
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "crawl": crawl_summary,
        "vulnerabilities": vulnerabilities,
        "total_vulns": len(vulnerabilities),
        "confirmed_count": len(confirmed),
        "unconfirmed_count": unconfirmed_count,
        "severity_stats": severity_stats,
        "severity_colors": config.SEVERITY_COLORS,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scan_meta": scan_meta or {},
    }


# --------------------------------------------------------------------------
# Rapport HTML (Jinja2)
# --------------------------------------------------------------------------
def render_html(context: dict[str, Any], filename: str | None = None) -> Path:
    env = Environment(
        loader=FileSystemLoader(str(config.TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report_template.html")
    html_out = template.render(**context)

    filename = filename or _timestamped("report", "html")
    out_path = config.REPORTS_DIR / filename
    out_path.write_text(html_out, encoding="utf-8")
    logger.info("HTML report generated: %s", out_path)
    return out_path


# --------------------------------------------------------------------------
# Rapport PDF (ReportLab)
# --------------------------------------------------------------------------
def _severity_pie(severity_stats: dict[str, int]) -> Drawing:
    """Camembert de répartition des sévérités."""
    data = [c for c in severity_stats.values()]
    labels = list(severity_stats.keys())

    d = Drawing(200, 150)
    pie = Pie()
    pie.x, pie.y = 30, 15
    pie.width = pie.height = 120

    # Si tout est à zéro, on met une part factice pour éviter une erreur.
    if sum(data) == 0:
        pie.data = [1]
        pie.labels = ["None"]
        pie.slices[0].fillColor = colors.HexColor("#4caf50")
    else:
        pie.data = data
        pie.labels = [f"{l} ({c})" for l, c in zip(labels, data)]
        for i, sev in enumerate(labels):
            pie.slices[i].fillColor = colors.HexColor(config.SEVERITY_COLORS[sev])
    pie.slices.strokeWidth = 0.5
    d.add(pie)
    return d


def _severity_bar(severity_stats: dict[str, int]) -> Drawing:
    """Histogramme des sévérités (impact visuel pour la soutenance)."""
    d = Drawing(280, 160)
    bc = VerticalBarChart()
    bc.x, bc.y = 30, 20
    bc.width, bc.height = 230, 120
    bc.data = [list(severity_stats.values())]
    bc.categoryAxis.categoryNames = list(severity_stats.keys())
    bc.valueAxis.valueMin = 0
    bc.bars[0].fillColor = colors.HexColor("#d9534f")
    bc.barWidth = 12
    d.add(bc)
    return d


def render_pdf(context: dict[str, Any], filename: str | None = None) -> Path:
    filename = filename or _timestamped("report", "pdf")
    out_path = config.REPORTS_DIR / filename

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm,
        title="XSS Analysis Report",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TitleBig", fontSize=22, leading=26, alignment=TA_CENTER,
        textColor=colors.white, spaceAfter=4, fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", fontSize=11, alignment=TA_CENTER,
        textColor=colors.HexColor("#c5cae9"), spaceAfter=0,
    ))
    styles.add(ParagraphStyle(
        name="H2", fontSize=14, leading=18, spaceBefore=4, spaceAfter=8,
        textColor=colors.HexColor("#1a237e"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="Cell", fontSize=8, leading=10, wordWrap="CJK",
    ))

    def section_header(title: str) -> list[Any]:
        """En-tête de section avec un bandeau coloré d'accent au-dessus du titre."""
        bar = Table([[""]], colWidths=[2.5 * cm], rowHeights=[0.12 * cm])
        bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#7c4dff"))]))
        return [Spacer(1, 0.3 * cm), bar, Spacer(1, 0.15 * cm), Paragraph(title, styles["H2"])]

    story: list[Any] = []

    # ---- Page de garde / en-tête (bandeau coloré plein) ----
    banner = Table([
        [Paragraph("🛡️ Automated XSS Analysis Report", styles["TitleBig"])],
        [Paragraph("DAST Platform — XSStrike &amp; DalFox orchestrated via Docker", styles["Subtitle"])],
    ], colWidths=[17.4 * cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a237e")),
        ("TOPPADDING", (0, 0), (-1, 0), 16),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 16),
        ("TOPPADDING", (0, 1), (-1, 1), 2),
    ]))
    story.append(banner)
    story.append(Spacer(1, 0.5 * cm))

    risk_color = {
        "High": colors.HexColor("#8e0000"),
        "Moderate": colors.HexColor("#c77700"),
        "Unconfirmed (possible false positives)": colors.HexColor("#777777"),
    }.get(context["risk_level"], colors.HexColor("#00895c"))

    meta_rows = [
        ["Target", context["target"]],
        ["Generated on", context["generated_at"]],
        ["Risk level", context["risk_level"]],
        ["Risk score", str(context["risk_score"])],
        ["Vulnerabilities detected", str(context["total_vulns"])],
    ]
    scan_level = (context.get("scan_meta") or {}).get("level")
    if scan_level:
        meta_rows.append(["Scan level", scan_level])
    meta_tbl = Table(meta_rows, colWidths=[5 * cm, 11 * cm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eaf6")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 2), (1, 2), "Helvetica-Bold"),
        ("TEXTCOLOR", (1, 2), (1, 2), risk_color),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c5cae9")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 0.5 * cm))

    # ---- Méthodologie ----
    story.extend(section_header("🧭 Methodology — how these vulnerabilities were found"))
    method_rows = [
        ["1. Reconnaissance", "The Playwright crawler renders the target's JavaScript, "
         "discovers URLs/forms/API calls, and spots DOM sinks. No injection at this stage."],
        ["2. Automated scan", "XSStrike and DalFox fuzz each discovered parameter inside "
         "disposable Docker containers (GET URLs and authenticated POST forms)."],
        ["3. Normalization", "Heterogeneous outputs are converted into a single schema "
         "(payload, parameter, context, severity), then deduplicated."],
        ["4. Real verification", "Each payload is replayed in a real browser by "
         "reconstructing the exact injection URL; 'Confirmed' = a JS dialog actually fired."],
    ]
    method_tbl = Table(
        [[Paragraph(f"<b>{_esc(a)}</b>", styles["Cell"]), Paragraph(_esc(b), styles["Cell"])]
         for a, b in method_rows],
        colWidths=[3.5 * cm, 13.9 * cm],
    )
    method_tbl.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#fafbff")]),
    ]))
    story.append(method_tbl)

    # ---- Graphiques ----
    story.extend(section_header("📊 Vulnerability breakdown by severity"))
    charts = Table(
        [[_severity_pie(context["severity_stats"]),
          _severity_bar(context["severity_stats"])]],
        colWidths=[8 * cm, 8 * cm],
    )
    charts.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(charts)

    # ---- Tableau récapitulatif des sévérités ----
    sev_rows = [["Severity", "Count"]]
    sev_rows += [[s, str(c)] for s, c in context["severity_stats"].items()]
    sev_tbl = Table(sev_rows, colWidths=[8 * cm, 8 * cm])
    sev_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]
    for i, (sev, _) in enumerate(context["severity_stats"].items(), start=1):
        sev_style.append(
            ("TEXTCOLOR", (0, i), (0, i), colors.HexColor(config.SEVERITY_COLORS[sev]))
        )
    sev_tbl.setStyle(TableStyle(sev_style))
    story.append(Spacer(1, 0.3 * cm))
    story.append(sev_tbl)

    # ---- Sinks DOM détectés (inventaire brut) ----
    sinks = context["crawl"].get("dom_sinks_list") or []
    if sinks:
        story.append(PageBreak())
        story.extend(section_header("🎯 Detected sinks (attack surface)"))
        story.append(Paragraph(
            "Places in the code where data reaching the DOM could be executed without "
            "escaping, whether detected/exploited or not — this is the "
            "\"sink\" half of the <b>source → sink</b> equation.",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.2 * cm))
        sink_rows = [["Page", "Sink", "Excerpt"]] + [
            [Paragraph(_esc(s.get("page", "")), styles["Cell"]),
             Paragraph(f"<font color='#8e0000'><b>{_esc(s.get('pattern', ''))}</b></font>", styles["Cell"]),
             Paragraph(_esc(s.get("snippet", ""))[:140], styles["Cell"])]
            for s in sinks[:40]
        ]
        sink_tbl = Table(sink_rows, colWidths=[5.5 * cm, 3.5 * cm, 8 * cm], repeatRows=1)
        sink_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]))
        story.append(sink_tbl)
        if len(sinks) > 40:
            story.append(Paragraph(
                f"<font size=8 color='#888'>… and {len(sinks) - 40} more (list truncated).</font>",
                styles["Normal"],
            ))

    # ---- Endpoints scannés ----
    endpoints = context["crawl"].get("injectable_urls_list") or []
    if endpoints:
        story.append(PageBreak())
        story.extend(section_header("🌐 Endpoints scanned by the DAST tools"))
        story.append(Paragraph(
            "Parameterized URLs actually passed to XSStrike/DalFox "
            "(links, forms, API calls intercepted during the crawl).",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.2 * cm))
        ep_rows = [["#", "URL"]] + [
            [str(i), Paragraph(_esc(u), styles["Cell"])]
            for i, u in enumerate(endpoints, start=1)
        ]
        ep_tbl = Table(ep_rows, colWidths=[1 * cm, 15 * cm], repeatRows=1)
        ep_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]))
        story.append(ep_tbl)

    # ---- Sécurité de la session / des cookies ----
    session = context["crawl"].get("session_analysis") or {}
    story.append(PageBreak())
    story.extend(section_header("🔐 Session &amp; cookie security"))
    if session and session.get("logged_in"):
        story.append(Paragraph(
            "Not an XSS finding by itself — this audits what happens "
            "<b>after</b> an XSS is confirmed: does the session mechanism let "
            "a single injected payload steal a full authenticated session?",
            styles["Normal"],
        ))
        if session.get("token_in_local_storage"):
            story.append(Spacer(1, 0.15 * cm))
            story.append(Paragraph(
                "<font color='#8e0000'><b>HIGH IMPACT</b></font> — Session "
                "token stored in <b>localStorage</b> (JWT), not an HttpOnly "
                "cookie: directly readable via "
                "<b>localStorage.getItem('token')</b>. Any XSS confirmed "
                "above can exfiltrate it for a full session takeover.",
                styles["Normal"],
            ))
        cookies = session.get("cookies") or []
        if cookies:
            story.append(Spacer(1, 0.25 * cm))
            cookie_rows = [["Cookie", "HttpOnly", "Secure", "SameSite", "Issues"]]
            for c in cookies:
                issues_txt = "; ".join(c.get("issues") or []) or "—"
                cookie_rows.append([
                    Paragraph(_esc(c.get("name", "")), styles["Cell"]),
                    "yes" if c.get("http_only") else "NO",
                    "yes" if c.get("secure") else "no",
                    _esc(c.get("same_site", "")),
                    Paragraph(_esc(issues_txt), styles["Cell"]),
                ])
            cookie_tbl = Table(
                cookie_rows, colWidths=[3 * cm, 1.8 * cm, 1.6 * cm, 2 * cm, 8.6 * cm],
                repeatRows=1,
            )
            cstyle = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
            ]
            for i, c in enumerate(cookies, start=1):
                if not c.get("http_only"):
                    cstyle.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor("#8e0000")))
                    cstyle.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
            cookie_tbl.setStyle(TableStyle(cstyle))
            story.append(cookie_tbl)
        else:
            story.append(Spacer(1, 0.15 * cm))
            story.append(Paragraph(
                "No cookies were set by the target during the authenticated "
                "session — consistent with a token-only / localStorage auth scheme.",
                styles["Normal"],
            ))
    elif session and session.get("note"):
        story.append(Paragraph(
            f"<font color='#c77700'><b>⚠ Authentication failed:</b></font> "
            f"{_esc(session['note'])}",
            styles["Normal"],
        ))
        dbg = session.get("debug") or {}
        if dbg:
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                "<b>Diagnostic — what the browser actually saw:</b>",
                styles["Normal"],
            ))
            story.append(Spacer(1, 0.1 * cm))
            dbg_rows = [
                ["Final URL", dbg.get("final_url", "—")],
                ["Cookies present", ", ".join(dbg.get("cookies_present") or []) or "—"],
                ["localStorage keys", ", ".join(dbg.get("local_storage_keys") or []) or "—"],
            ]
            dbg_tbl = Table(
                [[Paragraph(_esc(a), styles["Cell"]), Paragraph(_esc(b), styles["Cell"])]
                 for a, b in dbg_rows],
                colWidths=[4 * cm, 13.4 * cm],
            )
            dbg_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eaf6")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(dbg_tbl)

            netlog = dbg.get("network_log") or []
            if netlog:
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph(
                    "<font size=8.5><b>Network calls observed:</b></font>",
                    styles["Normal"],
                ))
                for line in netlog:
                    story.append(Paragraph(f"<font size=8>{_esc(line)}</font>", styles["Cell"]))
            else:
                story.append(Spacer(1, 0.15 * cm))
                story.append(Paragraph(
                    "<font size=8.5 color='#888'>No XHR/fetch calls were observed — this "
                    "site may validate sessions server-side on the main page load rather "
                    "than via a separate API call.</font>",
                    styles["Normal"],
                ))

            shot = dbg.get("screenshot")
            if shot and shot.get("image_b64"):
                try:
                    img_bytes = base64.b64decode(shot["image_b64"])
                    img = Image(io.BytesIO(img_bytes))
                    max_w = 9 * cm
                    if img.imageWidth > 0:
                        scale = min(1.0, max_w / img.imageWidth)
                        img.drawWidth = img.imageWidth * scale
                        img.drawHeight = img.imageHeight * scale
                    story.append(Spacer(1, 0.2 * cm))
                    story.append(img)
                except Exception as exc:
                    logger.debug("Capture de diagnostic illisible : %s", exc)
    else:
        story.append(Paragraph(
            "No authenticated session was established during this scan (the "
            "target may not expose a recognizable login form, or the "
            "disposable test account could not sign in) — session/cookie "
            "security could not be audited.",
            styles["Normal"],
        ))

    # ---- En-têtes de sécurité HTTP & CSP ----
    sec_headers = context["crawl"].get("security_headers") or {}
    story.append(PageBreak())
    story.extend(section_header("🛡️ Security headers &amp; CSP"))
    if sec_headers:
        story.append(Paragraph(
            "Not an XSS finding by itself — these headers determine whether "
            "the <b>browser</b> has a safety net (Content-Security-Policy in "
            "particular) even when a payload above successfully executes.",
            styles["Normal"],
        ))
        if sec_headers.get("csp_enforced"):
            badge = "<font color='#00895c'><b>CSP present &amp; enforced</b></font>"
        elif sec_headers.get("csp_present"):
            badge = "<font color='#c77700'><b>CSP present (report-only — not enforced)</b></font>"
        else:
            badge = "<font color='#8e0000'><b>No Content-Security-Policy</b></font>"
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph(badge, styles["Normal"]))

        hdr_findings = sec_headers.get("findings") or []
        if hdr_findings:
            story.append(Spacer(1, 0.25 * cm))
            hdr_rows = [["Header", "Severity", "Issue"]]
            for f in hdr_findings:
                hdr_rows.append([
                    Paragraph(_esc(f.get("header", "")), styles["Cell"]),
                    f.get("severity", ""),
                    Paragraph(_esc(f.get("issue", "")), styles["Cell"]),
                ])
            hdr_tbl = Table(hdr_rows, colWidths=[3.5 * cm, 2 * cm, 11.9 * cm], repeatRows=1)
            hstyle = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
            ]
            for i, f in enumerate(hdr_findings, start=1):
                sev = f.get("severity", "Medium")
                hstyle.append(
                    ("TEXTCOLOR", (1, i), (1, i), colors.HexColor(config.SEVERITY_COLORS.get(sev, "#777")))
                )
                hstyle.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
            hdr_tbl.setStyle(TableStyle(hstyle))
            story.append(hdr_tbl)
        else:
            story.append(Spacer(1, 0.15 * cm))
            story.append(Paragraph(
                "No issues found in the checked security headers.",
                styles["Normal"],
            ))

        if sec_headers.get("raw_csp"):
            story.append(Spacer(1, 0.2 * cm))
            story.append(Paragraph(
                f"<font size=7.5 color='#444'>{_esc(sec_headers['raw_csp'])}</font>",
                styles["Cell"],
            ))
    else:
        story.append(Paragraph(
            "Security headers were not checked during this scan (the crawl "
            "ended before the first page finished loading).",
            styles["Normal"],
        ))

    # ---- Détail des vulnérabilités ----
    story.append(PageBreak())
    story.extend(section_header("🐞 Vulnerability detail"))

    if not context["vulnerabilities"]:
        story.append(Paragraph(
            "No XSS vulnerability was detected during this analysis.",
            styles["Normal"],
        ))
    else:
        header = ["#", "Severity", "Type", "Tool", "Endpoint", "Parameter",
                   "Source → Sink", "Conf.", "Payload / Evidence"]
        rows = [header]
        for i, v in enumerate(context["vulnerabilities"], start=1):
            payload = (v.get("payload") or "")[:120]
            evidence = (v.get("evidence") or "")[:80]
            cell = Paragraph(
                f"<b>{_esc(payload)}</b><br/><font size=7 color='#666'>{_esc(evidence)}</font>",
                styles["Cell"],
            )
            confirmed_cell = Paragraph(
                "<font color='#4caf50'><b>YES</b></font>" if v.get("confirmed")
                else "<font color='#999'>no</font>",
                styles["Cell"],
            )
            source = v.get("source") or ""
            sink = v.get("sink") or v.get("context") or ""
            flow_cell = Paragraph(
                (f"<font color='#0d47a1'>🔵 {_esc(source)}</font><br/>"
                 f"<font color='#8e0000'>🎯 {_esc(sink)}</font>") if (source or sink)
                else _esc(v.get("context", "") or "-"),
                styles["Cell"],
            )
            rows.append([
                str(i),
                v.get("severity", ""),
                v.get("type", ""),
                v.get("tool", ""),
                Paragraph(_esc(v.get("url", "") or "-"), styles["Cell"]),
                Paragraph(_esc(v.get("parameter", "") or "-"), styles["Cell"]),
                flow_cell,
                confirmed_cell,
                cell,
            ])

        detail = Table(
            rows,
            colWidths=[0.6 * cm, 1.6 * cm, 1.8 * cm, 1.4 * cm, 2.6 * cm, 1.8 * cm,
                       2.2 * cm, 1 * cm, 3.6 * cm],
            repeatRows=1,
        )
        dstyle = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
        ]
        # Couleur de la pastille de sévérité + léger fond teinté par ligne,
        # et fond vert/gris pour la colonne "Confirmé".
        sev_tint = {
            "Critical": "#fbe9e9", "High": "#fdeeee", "Medium": "#fff6e6",
            "Low": "#eaf7fb", "Info": "#f2f2f2",
        }
        for i, v in enumerate(context["vulnerabilities"], start=1):
            sev = v.get("severity", "Medium")
            dstyle.append(
                ("TEXTCOLOR", (1, i), (1, i), colors.HexColor(config.SEVERITY_COLORS.get(sev, "#777")))
            )
            dstyle.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
            dstyle.append(
                ("BACKGROUND", (0, i), (0, i), colors.HexColor(sev_tint.get(sev, "#f2f2f2")))
            )
            dstyle.append((
                "BACKGROUND", (7, i), (7, i),
                colors.HexColor("#e3f7ec") if v.get("confirmed") else colors.HexColor("#eeeeee")
            ))
        detail.setStyle(TableStyle(dstyle))
        story.append(detail)

        # ---- Preuves visuelles (capture d'écran par navigateur réel) ----
        story.append(PageBreak())
        story.extend(section_header("📸 Visual evidence (real browser)"))
        story.append(Paragraph(
            "Each payload was replayed in a real browser (Playwright). A "
            "vulnerability is only marked <b>confirmed</b> if a JS dialog "
            "(alert/confirm/prompt) actually fired — proof of execution, "
            "not just a heuristic score from the scanner.",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        for i, v in enumerate(context["vulnerabilities"], start=1):
            story.append(Paragraph(
                f"#{i} — {_esc(v.get('tool', ''))} — "
                f"<font color='{'#4caf50' if v.get('confirmed') else '#999'}'>"
                f"<b>{'Confirmed' if v.get('confirmed') else 'Not confirmed'}</b></font> — "
                f"<font size=8>{_esc(v.get('url', '') or '-')}</font>",
                styles["Normal"],
            ))
            if v.get("source") or v.get("sink"):
                story.append(Paragraph(
                    f"<font size=8 color='#0d47a1'>🔵 Source: {_esc(v.get('source') or '—')}</font>"
                    "&nbsp;&nbsp;→&nbsp;&nbsp;"
                    f"<font size=8 color='#8e0000'>🎯 Sink: {_esc(v.get('sink') or v.get('context') or '—')}</font>",
                    styles["Normal"],
                ))
            steps = v.get("reproduction_steps") or []
            if steps:
                for j, step in enumerate(steps, start=1):
                    story.append(Paragraph(
                        f"<font size=8>{j}. {_esc(step)}</font>", styles["Cell"],
                    ))
            if v.get("reproduction_url"):
                story.append(Paragraph(
                    f"<font size=7.5 color='#444'>{_esc(v['reproduction_url'])}</font>",
                    styles["Cell"],
                ))
            if v.get("payload"):
                story.append(Paragraph(
                    f"<font size=8>{_esc(v['payload'])}</font>", styles["Cell"],
                ))
            if v.get("verification_note") and not steps:
                story.append(Paragraph(
                    f"<font size=8 color='#666'>{_esc(v['verification_note'])}</font>",
                    styles["Cell"],
                ))

            shots = v.get("screenshots") or (
                [{"label": "Result", "image_b64": v["screenshot_b64"]}]
                if v.get("screenshot_b64") else []
            )
            for j, shot in enumerate(shots, start=1):
                b64 = shot.get("image_b64")
                if not b64:
                    continue
                try:
                    img_bytes = base64.b64decode(b64)
                    img = Image(io.BytesIO(img_bytes))
                    max_w = 10 * cm
                    if img.imageWidth > 0:
                        scale = min(1.0, max_w / img.imageWidth)
                        img.drawWidth = img.imageWidth * scale
                        img.drawHeight = img.imageHeight * scale
                    story.append(Spacer(1, 0.15 * cm))
                    story.append(Paragraph(
                        f"<font size=7.5 color='#555'><b>{j}. {_esc(shot.get('label', ''))}</b></font>",
                        styles["Cell"],
                    ))
                    story.append(img)
                except Exception as exc:
                    logger.debug("Capture illisible pour la vulnérabilité #%d : %s", i, exc)
            story.append(Spacer(1, 0.5 * cm))

    story.append(Spacer(1, 0.8 * cm))
    story.append(Paragraph(
        "<font size=7 color='#999'>Automatically generated by XSS Automation "
        "Framework. For authorized testing only, against targets you have "
        "explicit permission to test.</font>",
        styles["Normal"],
    ))

    doc.build(story)
    logger.info("PDF report generated: %s", out_path)
    return out_path


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _timestamped(prefix: str, ext: str) -> str:
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def _esc(text: str) -> str:
    """Échappe le texte pour les Paragraph ReportLab (mini-langage XML)."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def generate_reports(
    target: str,
    crawl_summary: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    scan_meta: dict[str, Any] | None = None,
) -> dict[str, Path]:
    """
    Point d'entrée haut niveau : construit le contexte et génère les deux
    rapports. Renvoie {"html": Path, "pdf": Path, "context": dict}.
    """
    context = build_context(target, crawl_summary, vulnerabilities, scan_meta)
    return {
        "html": render_html(context),
        "pdf": render_pdf(context),
        "context": context,  # pratique pour l'affichage direct dans l'UI
    }
