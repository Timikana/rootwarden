"""
Une cause de connexion SSH est DITE au portail ; toute autre exception reste masquee.

2026-10-27, pile isolee, machine sans route : le backend journalisait
« Machine injoignable en SSH sur 10.10.99.99:22 : [Errno 113] No route to host »
et le portail recevait « Erreur interne ». La cause n'etait nulle part a l'ecran.
"""
import paramiko

from routes import helpers


class MachineInjoignable(paramiko.SSHException):
    """Meme NOM que la classe de `ssh_utils` (simulee dans ces tests)."""


class CleHoteChangee(paramiko.SSHException):
    pass


def _rend(app, e):
    with app.test_request_context():
        corps, statut = helpers.erreur_interne(e)
        return corps.get_json(), statut


def test_une_machine_injoignable_est_dite(app):
    e = MachineInjoignable('Machine injoignable en SSH sur 192.0.2.10:22 : [Errno 113] No route to host')

    corps, statut = _rend(app, e)

    assert statut == 500
    assert corps == {'success': False, 'message': str(e)}


def test_une_cle_d_hote_changee_et_un_refus_d_authentification_sont_dits(app):
    assert 'empreinte' in _rend(app, CleHoteChangee('empreinte differente'))[0]['message']
    assert 'Authentication failed' in _rend(app, paramiko.AuthenticationException('Authentication failed.'))[0]['message']


def test_toute_autre_exception_reste_masquee(app):
    # Temoin : un detail interne (requete SQL, chemin) ne doit jamais sortir.
    corps, statut = _rend(app, RuntimeError("SELECT * FROM users WHERE secret = 'x'"))

    assert (corps, statut) == ({'success': False, 'message': 'Erreur interne'}, 500)


def test_aucune_route_ne_rend_plus_erreur_interne_en_dur_apres_une_exception():
    # Garde : un `except Exception as e:` qui rendrait encore « Erreur interne »
    # en dur masquerait de nouveau la cause d'une machine injoignable.
    import re
    from pathlib import Path
    motif = re.compile(r"except Exception as \w+:\n(?:[^\n]*\n){0,6}?\s*return jsonify\(\{['\"]success['\"]: False, "
                       r"['\"]message['\"]: ['\"]Erreur interne['\"]\}\), 500")
    routes = Path(__file__).resolve().parents[1] / 'routes'
    fautifs = [f.name for f in routes.glob('*.py') if f.name != 'helpers.py' and motif.search(f.read_text(encoding='utf-8'))]
    assert fautifs == [], fautifs
    # Temoin du motif : il doit reconnaitre la forme d'avant.
    assert motif.search("except Exception as e:\n    logger.error(e)\n    return jsonify({'success': False, 'message': 'Erreur interne'}), 500")
