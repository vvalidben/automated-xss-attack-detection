"""
scanner_manager.py  (core/scanner_manager.py)
=============================================
Orchestrateur des scanners DAST via le **SDK Python `docker`**.

Chaque scanner (XSStrike, DalFox) tourne dans un conteneur Docker dédié,
isolé et jetable. Ce module :

    * construit la ligne de commande adaptée à chaque outil,
    * lance le conteneur avec un timeout strict,
    * récupère stdout/stderr,
    * tue proprement le conteneur en cas de dépassement de temps,
    * renvoie un `ScanResult` brut (le parsing est délégué à parser.py).

Avantages du SDK `docker` par rapport à subprocess :
    - gestion fine du cycle de vie (create/start/wait/kill/remove),
    - récupération structurée des logs,
    - pas de shell injection.

Prérequis : le démon Docker doit tourner et les images doivent être construites
(voir Dockerfile.xsstrike / Dockerfile.dalfox et le README).
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

import docker
from docker.errors import APIError, ContainerError, ImageNotFound, NotFound

import config

logger = logging.getLogger("scanner_manager")


# --------------------------------------------------------------------------
# Modèle de résultat brut
# --------------------------------------------------------------------------
@dataclass
class ScanResult:
    tool: str                          # "xsstrike" | "dalfox"
    target: str
    raw_output: str = ""               # stdout brut (JSON ou texte)
    stderr: str = ""
    exit_code: int | None = None
    duration_s: float = 0.0
    timed_out: bool = False
    error: str | None = None           # erreur d'orchestration (image manquante…)
    findings_format: str = "text"      # "json" | "jsonlines" | "text"
    method: str = "GET"                # méthode HTTP réellement testée (GET | POST)
    source_page: str = ""              # page où le formulaire POST a été découvert (si POST)

    def ok(self) -> bool:
        return self.error is None and not self.timed_out


# --------------------------------------------------------------------------
# Gestionnaire principal
# --------------------------------------------------------------------------
class ScannerManager:
    def __init__(self) -> None:
        # Connexion au démon Docker (via socket/pipe selon l'OS).
        try:
            self.client = docker.from_env()
            self.client.ping()
            self._docker_ok = True
        except Exception as exc:  # démon indisponible
            logger.error("Impossible de contacter le démon Docker : %s", exc)
            self.client = None
            self._docker_ok = False

    # ---- Utilitaires ---------------------------------------------------
    @staticmethod
    def _rewrite_host(url: str) -> str:
        """
        Remplace le host de l'URL par TARGET_HOST_OVERRIDE si défini.

        Nécessaire sous Docker Desktop : depuis un conteneur, `localhost`
        pointe vers le conteneur lui-même, pas vers Juice Shop sur l'hôte.
        On substitue alors `host.docker.internal`.
        """
        override = config.TARGET_HOST_OVERRIDE.strip()
        if not override:
            return url
        parsed = urlparse(url)
        host = override
        if parsed.port:
            host = f"{override}:{parsed.port}"
        return urlunparse(parsed._replace(netloc=host))

    def _run_container(
        self, image: str, command: list[str], tool: str, target: str,
        stop_event: threading.Event | None = None,
    ) -> ScanResult:
        """
        Lance un conteneur, attend sa fin (avec timeout) et récupère les logs.
        Gère explicitement : image manquante, timeout, erreur du démon.
        """
        result = ScanResult(tool=tool, target=target)

        if not self._docker_ok:
            result.error = "Démon Docker injoignable (Docker est-il démarré ?)"
            return result

        container = None
        start = time.monotonic()

        # Options de lancement. On n'ajoute `extra_hosts` (résolution de
        # host.docker.internal sous Linux) QUE hors mode réseau "host", car
        # certaines versions de Docker refusent extra_hosts avec --network host.
        run_kwargs: dict = {
            "image": image,
            "command": command,
            "detach": True,
            "network_mode": config.DOCKER_NETWORK_MODE,
            "remove": False,
        }
        if config.DOCKER_NETWORK_MODE != "host":
            run_kwargs["extra_hosts"] = {"host.docker.internal": "host-gateway"}

        try:
            logger.info("[%s] docker run %s %s", tool, image, " ".join(command))
            container = self.client.containers.run(**run_kwargs)

            # Attente par sondage (1s) plutôt qu'un unique `container.wait()`
            # bloquant : ça permet de vérifier `stop_event` en cours de route
            # et de tuer le conteneur immédiatement si l'utilisateur clique
            # sur "Pause", au lieu d'attendre jusqu'à SCANNER_TIMEOUT_S.
            deadline = time.monotonic() + config.SCANNER_TIMEOUT_S
            paused = False
            while True:
                try:
                    container.reload()
                    if container.status in ("exited", "dead"):
                        result.exit_code = (
                            container.attrs.get("State", {}).get("ExitCode")
                        )
                        break
                except Exception:
                    break  # conteneur déjà supprimé/inaccessible : on sort

                if stop_event is not None and stop_event.is_set():
                    paused = True
                    logger.info("[%s] Pause demandée — arrêt du conteneur", tool)
                    try:
                        container.kill()
                    except Exception:
                        pass
                    break

                if time.monotonic() > deadline:
                    result.timed_out = True
                    logger.warning("[%s] Timeout (%ss) — arrêt du conteneur",
                                   tool, config.SCANNER_TIMEOUT_S)
                    try:
                        container.kill()
                    except Exception:
                        pass
                    break

                time.sleep(1)

            if paused:
                result.error = "Analyse interrompue par l'utilisateur (pause)"

            # Récupération des logs (stdout+stderr séparés).
            try:
                result.raw_output = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                result.stderr = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )
            except Exception as exc:
                result.error = f"Lecture des logs impossible : {exc}"

        except ImageNotFound:
            result.error = (
                f"Image Docker introuvable : '{image}'. "
                f"Construis-la d'abord (voir README, section Docker)."
            )
        except (APIError, ContainerError) as exc:
            result.error = f"Erreur Docker : {exc}"
        except Exception as exc:  # pragma: no cover - filet de sécurité
            result.error = f"Erreur inattendue : {exc}"
        finally:
            result.duration_s = round(time.monotonic() - start, 2)
            # Nettoyage systématique du conteneur.
            if container is not None:
                try:
                    container.remove(force=True)
                except NotFound:
                    pass
                except Exception as exc:
                    logger.debug("Nettoyage conteneur %s : %s", tool, exc)

        return result

    # ---- Scanners individuels -----------------------------------------
    def run_xsstrike(self, url: str, stop_event: threading.Event | None = None) -> ScanResult:
        """
        XSStrike : analyse contextuelle + génération de payloads.
        L'entrypoint de l'image pointe déjà sur xsstrike.py.
        `--skip-dom` désactivé pour garder l'analyse DOM ; sortie texte parsée
        par parser.py (XSStrike n'a pas de sortie JSON native fiable).
        """
        target = self._rewrite_host(url)
        cmd = ["-u", target, "--skip", "--timeout", "10"]
        res = self._run_container(config.XSSTRIKE_IMAGE, cmd, "xsstrike", target, stop_event)
        res.findings_format = "text"
        return res

    def run_dalfox(
        self, url: str, stop_event: threading.Event | None = None,
        remote_payloads: bool = True,
    ) -> ScanResult:
        """
        DalFox : scanner XSS rapide. `--format json` donne une sortie
        structurée, idéale pour le parsing.
        `url` = mode analyse d'une URL unique avec ses paramètres.

        `remote_payloads` (réglé par le niveau de scan, voir
        config.SCAN_LEVELS) ajoute `--remote-payloads portswigger,payloadbox`
        : corpus communautaire élargi en plus des payloads intégrés de
        DalFox, au prix d'un scan plus long par endpoint (~+30-40s, resté
        sous SCANNER_TIMEOUT_S) — désactivé sur les niveaux légers (Low/
        Normal) pour rester rapide.
        """
        target = self._rewrite_host(url)
        cmd = ["url", target, "--format", "json", "--silence", "--no-color", "--skip-bav"]
        if remote_payloads:
            cmd += ["--remote-payloads", "portswigger,payloadbox"]
        res = self._run_container(config.DALFOX_IMAGE, cmd, "dalfox", target, stop_event)
        res.findings_format = "json"
        return res

    def run_dalfox_authenticated_post(
        self, url: str, post_data: str, auth_token: str,
        cookie_name: str = "token", source_page: str = "",
        stop_event: threading.Event | None = None,
        remote_payloads: bool = True,
    ) -> ScanResult:
        """
        DalFox en mode POST authentifié, pour les formulaires qui exigent une
        session (ex : /profile, formulaire "legacy" HTML de nom d'utilisateur).

        `run_dalfox`/`run_xsstrike` ne testent que des URLs GET anonymes : un
        champ de formulaire POST protégé par une session (comme le
        `username` de /profile) leur est invisible. On y injecte ici le
        jeton obtenu par le login jetable du crawler (voir
        `_register_and_login` dans crawler.py) via un cookie, et on laisse
        DalFox fuzzer le corps POST avec son corpus de payloads (bien plus
        large que ce qu'un test manuel peut couvrir) — utile même quand le
        résultat est négatif : ça confirme, avec un second outil indépendant,
        qu'aucun payload générique connu ne passe le filtre serveur.
        """
        target = self._rewrite_host(url)
        cmd = [
            "url", target,
            "-X", "POST", "-d", post_data,
            "-C", f"{cookie_name}={auth_token}",
            "--format", "json", "--silence", "--no-color", "--skip-bav",
        ]
        if remote_payloads:
            # Corpus communautaire (PortSwigger + PayloadBox) en plus des
            # payloads intégrés de DalFox : ce champ est protégé par un
            # assainisseur serveur, donc plus le corpus est large, plus la
            # confiance dans un résultat négatif est forte (~5x plus de
            # payloads testés, ~+35s) — réglé par le niveau de scan.
            cmd += ["--remote-payloads", "portswigger,payloadbox"]
        res = self._run_container(config.DALFOX_IMAGE, cmd, "dalfox", target, stop_event)
        res.findings_format = "json"
        res.method = "POST"
        res.source_page = source_page
        return res

    # ---- Pipeline complet ---------------------------------------------
    def scan_targets(
        self,
        urls: list[str],
        use_xsstrike: bool = True,
        use_dalfox: bool = True,
        max_urls: int = 15,
        stop_event: threading.Event | None = None,
        dalfox_remote_payloads: bool = True,
    ) -> list[ScanResult]:
        """
        Scanne une liste d'URLs avec les scanners activés.

        Les scans sont lancés en parallèle (thread pool) car chaque scan passe
        l'essentiel de son temps à attendre le conteneur Docker (I/O bound).
        On limite `max_urls` pour éviter des scans interminables en démo.
        """
        if not self._docker_ok:
            logger.error("Docker indisponible : aucun scan lancé.")
            return [
                ScanResult(
                    tool="orchestrator",
                    target="-",
                    error="Démon Docker injoignable. Démarre Docker puis réessaie.",
                )
            ]

        # On priorise les URLs comportant des paramètres (injectables).
        prioritized = sorted(urls, key=lambda u: (urlparse(u).query == ""))[:max_urls]

        jobs: list[tuple[str, str]] = []
        for url in prioritized:
            if use_xsstrike:
                jobs.append(("xsstrike", url))
            if use_dalfox:
                jobs.append(("dalfox", url))

        results: list[ScanResult] = []
        # Parallélisme raisonnable pour ne pas saturer la machine de démo.
        max_workers = min(4, max(1, len(jobs)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for tool, url in jobs:
                # Pause demandée : on arrête de SOUMETTRE de nouveaux jobs.
                # Ceux déjà en vol se terminent (ou sont tués via stop_event,
                # voir _run_container) au lieu d'être abandonnés à moitié.
                if stop_event is not None and stop_event.is_set():
                    break
                if tool == "xsstrike":
                    fut = pool.submit(self.run_xsstrike, url, stop_event)
                else:
                    fut = pool.submit(self.run_dalfox, url, stop_event, dalfox_remote_payloads)
                futures[fut] = (tool, url)

            for fut in concurrent.futures.as_completed(futures):
                tool, url = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:
                    results.append(
                        ScanResult(tool=tool, target=url, error=f"Job échoué : {exc}")
                    )

        return results


# --------------------------------------------------------------------------
# Exécution directe (debug) — python -m core.scanner_manager
# --------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mgr = ScannerManager()
    demo_url = config.DEFAULT_TARGET + "/rest/products/search?q=test"
    out = mgr.scan_targets([demo_url])
    for r in out:
        print(json.dumps(r.__dict__, indent=2, ensure_ascii=False)[:1500])
