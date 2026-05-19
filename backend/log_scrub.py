"""
log_scrub.py - Filtre logging qui scrubbe les secrets avant ecriture.

Patch A09-04 + A09-NEW-01 (OWASP A09 Logging & Monitoring Failures) :
Centralise le SecretScrubFilter pour qu'il soit applique a TOUS les handlers
de logging (server.log, deployment.log, iptables.log, update_servers.log,
graylog GELF, etc.), pas seulement server.log.

Usage :
    from log_scrub import attach_scrub
    handler = logging.FileHandler('/app/logs/deployment.log')
    attach_scrub(handler)
    logger.addHandler(handler)

Ou bien sur le root logger :
    from log_scrub import install_scrub_on_root
    install_scrub_on_root()
"""

import re
import logging


# Patterns scrub : passwords, tokens, api_keys, OpenCVE tokens.
# Append des patterns specifiques quand de nouveaux secrets sont introduits.
_SECRET_PATTERNS = [
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)", re.IGNORECASE), r"\1***SCRUBBED***"),
    (re.compile(r"(token['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)", re.IGNORECASE), r"\1***SCRUBBED***"),
    (re.compile(r"(WAZUH_REGISTRATION_PASSWORD=)(\S+)"), r"\1***SCRUBBED***"),
    (re.compile(r"(--?(?:registration[-_])?password[=\s]+)(\S+)", re.IGNORECASE), r"\1***SCRUBBED***"),
    (re.compile(r"(api[_-]?key['\"]?\s*[:=]\s*['\"]?)([^'\"\s,}]+)", re.IGNORECASE), r"\1***SCRUBBED***"),
    (re.compile(r"(authorization:\s*bearer\s+)(\S+)", re.IGNORECASE), r"\1***SCRUBBED***"),
    (re.compile(r"(opc_org\.[A-Za-z0-9_.-]+)"), "***OPENCVE-TOKEN-SCRUBBED***"),
    # Cles SSH inline (BEGIN ... PRIVATE KEY ... END)
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
     "-----SCRUBBED PRIVATE KEY-----"),
]


class SecretScrubFilter(logging.Filter):
    """Rewrite log records to scrub credentials/tokens before write."""

    def filter(self, record):
        try:
            msg = record.getMessage()
            for pat, repl in _SECRET_PATTERNS:
                msg = pat.sub(repl, msg)
            record.msg = msg
            record.args = ()
        except Exception:
            pass
        return True


# Singleton filter instance (un seul objet a attacher partout).
_scrub_filter = SecretScrubFilter()


def attach_scrub(handler: logging.Handler) -> logging.Handler:
    """Attache le scrub filter au handler. Idempotent."""
    # Ne pas dupliquer si deja present
    for f in handler.filters:
        if isinstance(f, SecretScrubFilter):
            return handler
    handler.addFilter(_scrub_filter)
    return handler


def install_scrub_on_root() -> None:
    """Installe le scrub sur tous les handlers du root logger (et futurs)."""
    root = logging.getLogger()
    for h in root.handlers:
        attach_scrub(h)
    # Patch addHandler pour auto-attacher sur les futurs handlers.
    if not getattr(root, '_rw_scrub_patched', False):
        original = root.addHandler
        def patched(handler):
            attach_scrub(handler)
            original(handler)
        root.addHandler = patched
        root._rw_scrub_patched = True
