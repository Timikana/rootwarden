"""
routes/settings.py - Les reglages qu'une interface peut ANNONCER.

Routes :
    GET /settings/announceable - valeurs EFFECTIVES d'une liste fermee de reglages

══ POURQUOI CETTE ROUTE EXISTE ═══════════════════════════════════════════════

Trois fois le 2026-08-27, un ecran a eu besoin d'une valeur qui vit dans un
conteneur qu'il ne voit pas : le numero de version, la duree de reversibilite de
la rotation de cle, la retention d'un journal. Chaque fois, les deux issues
etaient de coder le nombre en dur ou de ne rien afficher.

    Coder en dur un nombre qu'on affiche comme une GARANTIE est pire que ne pas
    l'afficher : un exploitant qui change le reglage croira que l'ecran le sait.

UNE SEULE ROUTE, PAS UNE PAR VALEUR. Douze routes pour douze nombres seraient
douze occasions d'en oublier une, et le treizieme reglage n'aurait pas de
porteur.

══ LA LISTE EST FERMEE, ET C'EST LA LEcON DE V10a ════════════════════════════

Elle est ENUMEREE ici, jamais derivee d'un motif sur `os.environ`. Un
`*_ENABLED` d'aujourd'hui est inoffensif ; le reglage qu'on ajoutera demain ne
l'est pas necessairement, et un filtre par motif l'exposerait sans que personne
ne l'ait decide.

C'est exactement le defaut de V10a : la valeur d'un override devenait une ligne
de configuration d'agent — sur Zabbix un `UserParameter`, donc l'execution d'une
commande. La parade retenue avait ete une interface a LISTE FERMEE, et c'est la
meme ici. « Ne pas offrir d'entree libre plutot que la valider. »

Rien de ce qui suit n'est un secret, une adresse ou un identifiant : des durees,
des bornes, des drapeaux. Un reglage sensible ne passe pas par cette route,
meme s'il faut l'annoncer.

══ LA VALEUR RENDUE EST CELLE QUE LE BACKEND EMPLOIE ════════════════════════

Elle est lue DANS LE MODULE QUI S'EN SERT, jamais re-derivee de
`os.getenv(...)`. Re-parser l'environnement ici rejouerait le defaut que cette
route est censee supprimer : `int(os.getenv('X', '30'))` rend 30 quand la
variable est absente, ce qui decrit le code et non le comportement — et les deux
peuvent diverger, ne serait-ce que par une difference de coercition
(`.lower() == 'true'` contre `bool(...)`).

Quand une valeur ne peut pas etre resolue, elle est rendue a `null` ET son nom
apparait dans `non_resolus`. **Un champ absent se lit comme « rien a dire »** ;
c'est la lecon d'E-183 puis d'E-194, et elle vaut ici aussi : une interface doit
pouvoir distinguer « ce reglage vaut faux » de « je n'ai pas pu le lire ».
"""

import logging
from flask import Blueprint, jsonify

from routes.helpers import require_api_key, threaded_route

bp = Blueprint('settings', __name__)
logger = logging.getLogger('rootwarden')


def _depuis_config(nom, conversion):
    """Valeur effective lue dans `Config`, ou None si elle n'est pas resoluble."""
    from config import Config
    return conversion(getattr(Config, nom))


def _depuis_module(module, attribut, conversion):
    """Valeur effective lue dans le module QUI S'EN SERT, ou None.

    Deux des douze ne vivent pas dans `Config` : `PLATFORM_KEY_ARCHIVE_DAYS` est
    une constante de `ssh_key_manager`, et `WEBHOOK_ENABLED` de `webhooks`. Les
    lire la ou elles sont employees plutot que de re-lire l'environnement est ce
    qui garantit que la route decrit le COMPORTEMENT.

    L'import est tardif : `webhooks` est remplace par un `MagicMock` dans
    `backend/tests/conftest.py`, et la conversion echouera alors proprement
    plutot que de rendre un objet non serialisable.
    """
    import importlib
    return conversion(getattr(importlib.import_module(module), attribut))


# ── LA LISTE FERMEE ─────────────────────────────────────────────────────────
#
# (cle rendue, resolveur). Ajouter une ligne ici est une DECISION : elle expose
# la valeur a toute interface qui interroge la route.
_ANNONCABLES = (
    # Durees et bornes
    ('platform_key_archive_days',
     lambda: _depuis_module('ssh_key_manager', 'ARCHIVE_RETENTION_DAYS', int)),
    ('ssh_timeout',            lambda: _depuis_config('SSH_TIMEOUT', int)),
    ('cve_max_pages',          lambda: _depuis_config('CVE_MAX_PAGES', int)),
    ('cve_page_limit',         lambda: _depuis_config('CVE_PAGE_LIMIT', int)),
    # Drapeaux de fonctionnalite
    ('approval_enabled',       lambda: _depuis_config('APPROVAL_ENABLED', bool)),
    ('mail_enabled',           lambda: _depuis_config('MAIL_ENABLED', bool)),
    ('chatops_enabled',        lambda: _depuis_config('CHATOPS_ENABLED', bool)),
    ('webhook_enabled',
     lambda: _depuis_module('webhooks', 'WEBHOOK_ENABLED', bool)),
    ('ticketing_enabled',      lambda: _depuis_config('TICKETING_ENABLED', bool)),
    ('wazuh_enabled',          lambda: _depuis_config('WAZUH_ENABLED', bool)),
    ('cve_enrich_enabled',     lambda: _depuis_config('CVE_ENRICH_ENABLED', bool)),
    ('nvd_enrichment_enabled', lambda: _depuis_config('NVD_ENRICHMENT_ENABLED', bool)),
)


@bp.route('/settings/announceable', methods=['GET'])
@require_api_key
@threaded_route
def announceable():
    """Rend la valeur EFFECTIVE des reglages qu'une interface peut annoncer.

    ══ LA GARDE EST `@require_api_key` SEULE, ET C'EST DELIBERE ═════════════

    C'est une LECTURE, et rien de ce qu'elle rend n'est un secret : des durees,
    des bornes et des drapeaux, tous deja visibles dans le fichier d'exemple
    livre avec le produit. Aucun role ni permission n'est exige parce qu'aucune
    des douze valeurs ne distingue un utilisateur d'un autre — les exiger
    donnerait a croire qu'il y a la quelque chose a proteger.

    Je l'ecris plutot que de laisser la question ouverte : ce depot compte trois
    commentaires qui affirmaient une garde plus stricte que le code, et un qui
    justifiait une absence de garde par un motif sans rapport avec
    l'autorisation. Une absence de garde se DECLARE, avec son motif.

    Ce qui garde reellement cette route est la LISTE FERMEE, pas un decorateur :
    elle ne peut rendre que ce qui y est enumere.
    """
    valeurs, non_resolus = {}, []
    for cle, resolveur in _ANNONCABLES:
        try:
            valeurs[cle] = resolveur()
        except Exception as e:
            # `null` ET le nom dans `non_resolus` : une interface doit pouvoir
            # distinguer « ce reglage vaut faux » de « je n'ai pas pu le lire ».
            valeurs[cle] = None
            non_resolus.append(cle)
            logger.warning("settings/announceable : %s non resolu (%s)", cle, e)

    return jsonify({
        'success': True,
        'settings': valeurs,
        # Toujours present, meme vide — un champ absent se lit « rien a dire ».
        'non_resolus': non_resolus,
    })
