"""
Une cle d'API agit au nom de SON CREATEUR — audit du 2026-10-13, B-1.

Le backend relit le role en base (`get_current_user`), mais il prend
`X-User-ID` dans l'EN-TETE : quiconque detient une cle d'API pleine portee
peut annoncer `X-User-ID: <superadmin>` et agir en role 3 sur tout le parc.

Desormais :
  - la cle INTERNE du portail (`auto_generated=1`) relaie l'identite de chaque
    utilisateur : l'en-tete reste lu ;
  - une cle creee par un utilisateur agit au nom de `created_by`, quel que soit
    l'en-tete ;
  - une cle sans createur connu GARDE l'ancien comportement, journalise : ce peut
    etre la cle du portail lui-meme, anterieure a la colonne `auto_generated`.
    La priver d'identite ferait tomber toute la production.

`mock_db` (conftest) rend, pour `SELECT ... FROM users WHERE id = %s`, un role
derive de l'id : 2 -> role 3, 10 -> role 1.
"""
from flask import g

from routes import helpers


def _identite(app, cle, en_tete):
    with app.test_request_context(headers={'X-User-ID': str(en_tete)}):
        if cle is not None:
            g._rw_cle_api = cle
        return helpers.get_current_user()


def test_une_cle_d_utilisateur_ne_peut_pas_s_annoncer_superadmin(app, mock_db):
    cle = {'id': 7, 'created_by': 10, 'interne': False}   # creee par un role 1

    uid, role = _identite(app, cle, en_tete=2)            # s'annonce superadmin

    assert (uid, role) == (10, 1), f"la cle a obtenu l'identite annoncee : {(uid, role)}"


def test_la_cle_interne_du_portail_relaie_l_identite(app, mock_db):
    cle = {'id': 1, 'created_by': None, 'interne': True}

    assert _identite(app, cle, en_tete=2) == (2, 3)
    assert _identite(app, cle, en_tete=10) == (10, 1)


def test_une_cle_sans_createur_garde_l_ancien_comportement_et_le_journalise(app, mock_db, caplog):
    cle = {'id': 9, 'created_by': None, 'interne': False}

    assert _identite(app, cle, en_tete=2) == (2, 3)
    assert any('sans createur' in r.getMessage() for r in caplog.records), \
        'une cle sans createur doit etre signalee au journal'


def test_sans_information_de_cle_le_comportement_est_inchange(app, mock_db):
    # Temoin : le chemin de secours (API_KEY_BOOTSTRAP) ne pose pas d'info de cle.
    assert _identite(app, None, en_tete=2) == (2, 3)


class _Cur:
    def __init__(self, lignes):
        self._lignes = lignes
        self._q = ''

    def execute(self, q, p=()):
        self._q = q

    def fetchone(self):
        if 'COUNT(*)' in self._q:
            return {'cnt': 1}
        if 'FROM api_keys' in self._q:
            return self._lignes
        return None


class _Conn:
    def __init__(self, ligne):
        self._ligne = ligne

    def cursor(self, dictionary=False):
        return _Cur(self._ligne)

    def commit(self):
        pass

    def close(self):
        pass


def test_la_validation_memorise_le_createur_et_le_caractere_interne(app, monkeypatch):
    ligne = {'id': 7, 'name': 'integration', 'scope_json': None, 'revoked_at': None,
             'created_by': 10, 'auto_generated': 0}
    monkeypatch.setattr(helpers, 'get_db_connection', lambda: _Conn(ligne))

    with app.test_request_context('/list_machines'):
        ok, _ = helpers._validate_api_key_from_db('rw_live_cle', '/list_machines')
        assert ok is True
        assert g._rw_cle_api == {'id': 7, 'created_by': 10, 'interne': False}
