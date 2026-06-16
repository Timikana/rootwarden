#!/usr/bin/env python3
"""
cve_enrich.py - Enrichissement EPSS + CISA KEV des findings CVE (RootWarden).

Role :
    Le score CVSS mesure la *severite theorique* d'une vulnerabilite, pas la
    probabilite qu'elle soit reellement exploitee. Deux sources gratuites
    complementaires permettent de prioriser :

      - EPSS (FIRST.org) : probabilite (0..1) qu'une CVE soit exploitee dans
        les 30 prochains jours. https://api.first.org/data/v1/epss
      - CISA KEV         : catalogue des vulnerabilites *activement exploitees*
        in-the-wild (Known Exploited Vulnerabilities). Une CVE presente dans le
        KEV est une urgence absolue, quel que soit son CVSS.

    Ce module recupere ces deux signaux pour une liste de CVE, calcule un score
    de priorite consolide et annote les findings en place (dict mutation).

Strategie reseau / securite :
    - Reutilise le guard SSRF de cve_scanner (_safe_get / _url_is_safe_external).
    - Cache memoire TTL (EPSS par CVE, KEV catalogue complet) pour eviter de
      marteler les API a chaque scan.
    - Best-effort : toute erreur reseau laisse les findings inchanges (failsafe),
      le scan CVE n'echoue jamais a cause de l'enrichissement.
"""

import time
import logging

import requests
from config import Config

# Guard SSRF + GET securise mutualises avec le scanner CVE.
from cve_scanner import _safe_get, _url_is_safe_external

_log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# Client EPSS (FIRST.org)
# ────────────────────────────────────────────────────────────────────────────

class EPSSClient:
    """
    Client pour l'API EPSS de FIRST.org.

    L'API accepte une liste de CVE separees par virgule :
        GET /data/v1/epss?cve=CVE-2024-1,CVE-2024-2&pretty=false
    Reponse : {"data": [{"cve": "...", "epss": "0.97", "percentile": "0.99",
                          "date": "2026-06-14"}]}

    On batch par paquets de ~80 CVE (limite raisonnable de longueur d'URL) et
    on cache chaque CVE individuellement (TTL configurable). Les CVE absentes
    de la reponse (pas de score EPSS publie) sont memorisees comme None pour
    eviter de les re-demander en boucle.
    """

    _BATCH = 80

    def __init__(self):
        self.url = Config.EPSS_API_URL.rstrip('/')
        self.cache_ttl = Config.CVE_ENRICH_CACHE_TTL
        # cve_id -> (ts, {'epss': float, 'percentile': float} | None)
        self._cache: dict[str, tuple[float, dict | None]] = {}

    def get_scores(self, cve_ids: list[str]) -> dict[str, dict]:
        """
        Retourne {cve_id: {'epss': float, 'percentile': float}} pour les CVE
        ayant un score EPSS publie. Les CVE sans score sont absentes du dict.
        """
        now = time.time()
        out: dict[str, dict] = {}
        to_fetch: list[str] = []
        for cid in {c for c in cve_ids if c}:
            cached = self._cache.get(cid)
            if cached and (now - cached[0] < self.cache_ttl):
                if cached[1] is not None:
                    out[cid] = cached[1]
            else:
                to_fetch.append(cid)

        if not to_fetch:
            return out

        if not _url_is_safe_external(self.url):
            _log.warning("EPSS URL refusee (SSRF guard) : %s", self.url)
            return out

        for i in range(0, len(to_fetch), self._BATCH):
            batch = to_fetch[i:i + self._BATCH]
            fetched: set[str] = set()
            try:
                resp = _safe_get(self.url, params={'cve': ','.join(batch),
                                                   'pretty': 'false'}, timeout=15)
                resp.raise_for_status()
                data = resp.json()
                for row in data.get('data', []) or []:
                    cid = row.get('cve')
                    if not cid:
                        continue
                    try:
                        rec = {
                            'epss': float(row.get('epss') or 0.0),
                            'percentile': float(row.get('percentile') or 0.0),
                        }
                    except (TypeError, ValueError):
                        continue
                    self._cache[cid] = (now, rec)
                    out[cid] = rec
                    fetched.add(cid)
            except Exception as e:
                _log.debug("EPSS batch fetch failed (%d CVE): %s", len(batch), e)
                # Pas de mise en cache negative en cas d'erreur reseau (on
                # reessaiera au prochain scan).
                continue
            # CVE du batch sans score publie -> cache negatif (None)
            for cid in batch:
                if cid not in fetched:
                    self._cache[cid] = (now, None)

        return out


# ────────────────────────────────────────────────────────────────────────────
# Catalogue CISA KEV
# ────────────────────────────────────────────────────────────────────────────

class KEVCatalog:
    """
    Charge et met en cache le catalogue CISA KEV (Known Exploited Vulnerabilities).

    Source : un gros JSON {"vulnerabilities": [{"cveID": "...",
             "dateAdded": "YYYY-MM-DD", ...}]}. On en extrait une map
             {cve_id: date_added}. Cache TTL long (24h par defaut) : le
             catalogue evolue lentement.
    """

    def __init__(self):
        self.url = Config.KEV_CATALOG_URL
        self.cache_ttl = Config.KEV_CACHE_TTL
        self._ts = 0.0
        self._map: dict[str, str] = {}

    def _refresh(self) -> None:
        if not _url_is_safe_external(self.url):
            _log.warning("KEV URL refusee (SSRF guard) : %s", self.url)
            return
        try:
            resp = _safe_get(self.url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            new_map: dict[str, str] = {}
            for v in data.get('vulnerabilities', []) or []:
                cid = v.get('cveID')
                if cid:
                    new_map[cid] = v.get('dateAdded') or ''
            if new_map:
                self._map = new_map
                self._ts = time.time()
                _log.info("Catalogue CISA KEV charge : %d CVE", len(new_map))
        except Exception as e:
            _log.debug("KEV catalogue fetch failed: %s", e)

    def get_map(self) -> dict[str, str]:
        """Retourne {cve_id: date_added}, rafraichi si le cache est expire."""
        if time.time() - self._ts >= self.cache_ttl or not self._map:
            self._refresh()
        return self._map


_epss: EPSSClient | None = None
_kev: KEVCatalog | None = None


def get_epss_client() -> EPSSClient:
    global _epss
    if _epss is None:
        _epss = EPSSClient()
    return _epss


def get_kev_catalog() -> KEVCatalog:
    global _kev
    if _kev is None:
        _kev = KEVCatalog()
    return _kev


# ────────────────────────────────────────────────────────────────────────────
# Calcul du score de priorite consolide
# ────────────────────────────────────────────────────────────────────────────

def compute_priority(cvss: float, epss: float | None, kev: bool) -> tuple[float, str]:
    """
    Combine CVSS (severite) + EPSS (probabilite d'exploitation) + KEV
    (exploitation averee) en un score 0..100 et un label de priorite.

    Logique :
      - KEV present            -> 100 / URGENT (exploitation in-the-wild averee).
      - Sinon : moyenne ponderee 50% CVSS (normalise /10) + 50% EPSS.
        Le label decoule du score :
          >= 70 -> HIGH | >= 40 -> MEDIUM | sinon LOW

    On garde le label distinct de la *severite* CVSS : une CVE CVSS 9.8 avec
    EPSS 0.01 (jamais exploitee) tombe en MEDIUM, alors qu'une CVSS 6.5 avec
    EPSS 0.95 remonte en HIGH. C'est tout l'interet de la priorisation EPSS.
    """
    cvss = max(0.0, min(10.0, float(cvss or 0.0)))
    if kev:
        return 100.0, 'URGENT'
    e = max(0.0, min(1.0, float(epss))) if epss is not None else 0.0
    score = round((cvss / 10.0) * 50.0 + e * 50.0, 1)
    if score >= 70:
        label = 'HIGH'
    elif score >= 40:
        label = 'MEDIUM'
    else:
        label = 'LOW'
    return score, label


def enrich_findings(findings: list[dict]) -> dict:
    """
    Annote en place chaque finding avec epss_score, epss_percentile, kev,
    kev_date_added, priority_score, priority_label.

    Args:
        findings : liste de dicts contenant au moins 'cve_id' et 'cvss'
                   (ou 'cvss_score').

    Returns:
        dict de stats {'epss': n, 'kev': n} (nombre de findings enrichis).
        Best-effort : en cas d'echec reseau, les findings restent partiellement
        ou non enrichis, mais on calcule toujours un priority_score base sur le
        CVSS seul (pour avoir un tri coherent).
    """
    if not findings:
        return {'epss': 0, 'kev': 0}

    cve_ids = [f.get('cve_id', '') for f in findings if f.get('cve_id')]

    epss_map: dict[str, dict] = {}
    kev_map: dict[str, str] = {}
    try:
        epss_map = get_epss_client().get_scores(cve_ids)
    except Exception as e:
        _log.debug("EPSS enrichment failed globally: %s", e)
    try:
        kev_map = get_kev_catalog().get_map()
    except Exception as e:
        _log.debug("KEV enrichment failed globally: %s", e)

    n_epss = n_kev = 0
    for f in findings:
        cid = f.get('cve_id', '')
        cvss = f.get('cvss', f.get('cvss_score', 0.0))

        epss_rec = epss_map.get(cid)
        epss_val = None
        if epss_rec:
            epss_val = epss_rec['epss']
            f['epss_score'] = round(epss_rec['epss'], 4)
            f['epss_percentile'] = round(epss_rec['percentile'], 4)
            n_epss += 1
        else:
            f['epss_score'] = None
            f['epss_percentile'] = None

        is_kev = cid in kev_map
        f['kev'] = 1 if is_kev else 0
        f['kev_date_added'] = kev_map.get(cid) or None
        if is_kev:
            n_kev += 1

        score, label = compute_priority(cvss, epss_val, is_kev)
        f['priority_score'] = score
        f['priority_label'] = label

    return {'epss': n_epss, 'kev': n_kev}
