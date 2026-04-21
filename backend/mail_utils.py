#!/usr/bin/env python3
"""
mail_utils.py - Envoi de rapports CVE par email au format HTML pour RootWarden.

Rôle :
    Génère un email HTML récapitulant les vulnérabilités CVE détectées sur un serveur
    et l'envoie via SMTP. Supporte deux modes TLS :
      - STARTTLS (port 587, Config.MAIL_SMTP_TLS=True)
      - SSL direct / SMTPS (port 465, Config.MAIL_SMTP_TLS=False)

Dépendances clés :
    - smtplib              : envoi SMTP (bibliothèque standard Python)
    - email.mime           : construction de l'email multipart/alternative
    - config.Config        : MAIL_ENABLED, MAIL_FROM, MAIL_TO, MAIL_SMTP_HOST,
                             MAIL_SMTP_PORT, MAIL_SMTP_TLS, MAIL_SMTP_USER,
                             MAIL_SMTP_PASSWORD

Sujet de l'email :
    Le sujet est automatiquement préfixé par :
      - "[CRITICAL]" si au moins une CVE critique est trouvée
      - "[HIGH]"     si aucune critique mais au moins une HIGH
      - sinon pas de préfixe de sévérité
"""
# mail_utils.py - Envoi de rapports CVE par email (RootWarden)
#
# Configuration (srv-docker.env) :
#   MAIL_ENABLED      true / false
#   MAIL_FROM         noreply@example.com
#   MAIL_TO           admin@example.com  (virgule pour plusieurs destinataires)
#   MAIL_SMTP_HOST    smtp.example.com
#   MAIL_SMTP_PORT    587
#   MAIL_SMTP_USER    (optionnel)
#   MAIL_SMTP_PASSWORD (optionnel)
#   MAIL_SMTP_TLS     true (STARTTLS) / false (SSL direct)

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from config import Config

_log = logging.getLogger(__name__)

# Couleurs par sévérité (HTML)
_SEV_COLORS = {
    'CRITICAL': '#dc2626',
    'HIGH':     '#ea580c',
    'MEDIUM':   '#d97706',
    'LOW':      '#65a30d',
    'NONE':     '#6b7280',
}


def _build_html(machine_name: str, ip: str, findings: list[dict],
                scan_date: str, min_cvss: float) -> str:
    """
    Construit le corps HTML du rapport CVE.

    Génère un email HTML responsive avec :
      - En-tête bleu avec titre et date du scan.
      - Tableau résumé : nom du serveur, IP, seuil CVSS.
      - Badges de comptage par sévérité (CRITICAL / HIGH / MEDIUM / LOW).
      - Tableau détaillé des CVE avec lien vers cve.org, package, version,
        sévérité colorée et résumé tronqué à 200 caractères.

    Args:
        machine_name (str) : Nom du serveur (affiché dans le rapport).
        ip           (str) : Adresse IP du serveur.
        findings     (list): Liste de dicts CVE (package, version, cve_id,
                             cvss, severity, summary).
        scan_date    (str) : Date/heure du scan (format libre, ex: "31/03/2026 14:00").
        min_cvss     (float): Seuil CVSS utilisé lors du scan.

    Returns:
        Chaîne HTML complète (str) prête à être attachée en MIMEText('html').
    """
    counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')}
    for f in findings:
        sev = f.get('severity', 'NONE')
        if sev in counts:
            counts[sev] += 1

    rows = ''
    for f in findings:
        sev   = f.get('severity', 'NONE')
        color = _SEV_COLORS.get(sev, '#6b7280')
        rows += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">
            <a href="https://www.cve.org/CVERecord?id={f['cve_id']}"
               style="color:#1d4ed8">{f['cve_id']}</a>
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{f['package']}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">{f['version']}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;
                     color:{color};font-weight:700;white-space:nowrap">
            {sev} ({f['cvss']})
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;
                     font-size:12px;color:#4b5563">{f.get('summary','')[:200]}</td>
        </tr>"""

    badge = lambda sev, c: (
        f'<span style="background:{_SEV_COLORS[sev]};color:white;'
        f'padding:2px 8px;border-radius:4px;font-size:13px;margin-right:6px">'
        f'{c} {sev}</span>'
    )

    return f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f9fafb;padding:24px;color:#111827">
  <div style="max-width:900px;margin:0 auto;background:white;
              border-radius:8px;overflow:hidden;
              box-shadow:0 1px 3px rgba(0,0,0,.1)">

    <div style="background:#1e3a8a;padding:24px 32px">
      <h1 style="margin:0;color:white;font-size:20px">
        🔐 Rapport de vulnérabilités CVE
      </h1>
      <p style="margin:4px 0 0;color:#93c5fd;font-size:14px">
        RootWarden - Scan du {scan_date}
      </p>
    </div>

    <div style="padding:24px 32px;border-bottom:1px solid #e5e7eb">
      <table>
        <tr>
          <td style="padding-right:32px">
            <div style="font-size:13px;color:#6b7280">Serveur</div>
            <div style="font-size:16px;font-weight:700">{machine_name}</div>
          </td>
          <td style="padding-right:32px">
            <div style="font-size:13px;color:#6b7280">Adresse IP</div>
            <div style="font-size:16px;font-weight:700">{ip}</div>
          </td>
          <td>
            <div style="font-size:13px;color:#6b7280">Seuil CVSS</div>
            <div style="font-size:16px;font-weight:700">{min_cvss}+</div>
          </td>
        </tr>
      </table>
    </div>

    <div style="padding:20px 32px;border-bottom:1px solid #e5e7eb">
      {badge('CRITICAL', counts['CRITICAL'])}
      {badge('HIGH',     counts['HIGH'])}
      {badge('MEDIUM',   counts['MEDIUM'])}
      {badge('LOW',      counts['LOW'])}
      <span style="font-size:13px;color:#6b7280">
        - {len(findings)} vulnérabilité(s) au total
      </span>
    </div>

    {'<p style="padding:24px 32px;color:#6b7280">Aucune vulnérabilité détectée au-dessus du seuil configuré.</p>'
      if not findings else f'''
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <thead>
        <tr style="background:#f1f5f9;color:#374151">
          <th style="padding:10px 12px;text-align:left">CVE</th>
          <th style="padding:10px 12px;text-align:left">Package</th>
          <th style="padding:10px 12px;text-align:left">Version</th>
          <th style="padding:10px 12px;text-align:left">Sévérité</th>
          <th style="padding:10px 12px;text-align:left">Résumé</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>'''}

    <div style="padding:16px 32px;background:#f9fafb;
                font-size:12px;color:#9ca3af;text-align:center">
      Généré par <strong>RootWarden</strong> - Gestion SSH centralisée
    </div>
  </div>
</body>
</html>"""


def send_cve_report(machine_name: str, ip: str, findings: list[dict],
                    min_cvss: float = 0.0, scan_date: str = None) -> bool:
    """
    Envoie un rapport CVE HTML par email via SMTP.

    Ne fait rien (retourne False) si ``Config.MAIL_ENABLED`` est False ou si
    les variables MAIL_TO, MAIL_FROM ou MAIL_SMTP_HOST sont absentes.

    Le sujet est préfixé automatiquement selon la sévérité maximale trouvée :
      - "[CRITICAL]" si findings contient au moins une CVE critique.
      - "[HIGH]"     sinon si findings contient au moins une CVE high.

    Connexion SMTP :
      - STARTTLS (port 587) si ``Config.MAIL_SMTP_TLS`` est True.
      - SSL direct (port 465) sinon.
    L'authentification SMTP est optionnelle (ignorée si USER/PASSWORD sont vides).

    Args:
        machine_name (str) : Nom du serveur scanné.
        ip           (str) : Adresse IP du serveur.
        findings     (list): Liste de dicts CVE à inclure dans le rapport.
        min_cvss     (float): Seuil CVSS utilisé lors du scan (affiché dans le rapport).
        scan_date    (str) : Date du scan (optionnel, défaut : datetime.now()).

    Returns:
        True si l'email a été envoyé avec succès, False sinon.
    """
    if not Config.MAIL_ENABLED:
        return False

    missing = [v for v in ('MAIL_TO', 'MAIL_FROM', 'MAIL_SMTP_HOST')
               if not getattr(Config, v, '')]
    if missing:
        _log.warning("Mail activé mais variables manquantes : %s", missing)
        return False

    now_str = scan_date or datetime.now().strftime('%d/%m/%Y %H:%M')
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high     = sum(1 for f in findings if f.get('severity') == 'HIGH')

    subject = f"[RootWarden] CVE - {machine_name} ({ip}) - {len(findings)} finding(s)"
    if critical:
        subject = f"[CRITICAL] {subject}"
    elif high:
        subject = f"[HIGH] {subject}"

    html = _build_html(machine_name, ip, findings, now_str, min_cvss)

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = Config.MAIL_FROM
    msg['To']      = Config.MAIL_TO
    msg.attach(MIMEText(html, 'html', 'utf-8'))

    recipients = [r.strip() for r in Config.MAIL_TO.split(',') if r.strip()]

    try:
        port = Config.MAIL_SMTP_PORT
        if Config.MAIL_SMTP_TLS:
            # STARTTLS (port 587)
            smtp = smtplib.SMTP(Config.MAIL_SMTP_HOST, port, timeout=15)
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
        elif port == 465:
            # SMTPS (port 465)
            smtp = smtplib.SMTP_SSL(Config.MAIL_SMTP_HOST, port, timeout=15)
        else:
            # Plain SMTP sans chiffrement (port 25, relay IP-whitelisté)
            smtp = smtplib.SMTP(Config.MAIL_SMTP_HOST, port, timeout=15)
            smtp.ehlo()

        if Config.MAIL_SMTP_USER and Config.MAIL_SMTP_PASSWORD:
            smtp.login(Config.MAIL_SMTP_USER, Config.MAIL_SMTP_PASSWORD)

        smtp.sendmail(Config.MAIL_FROM, recipients, msg.as_string())
        smtp.quit()
        _log.info("Rapport CVE envoyé : %s → %s", machine_name, Config.MAIL_TO)
        return True

    except Exception as e:
        _log.error("Envoi email échoué (%s) : %s", machine_name, e)
        return False
