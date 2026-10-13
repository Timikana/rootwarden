"""
Le token Telegraf stocke en clair — audit du 2026-10-13, M-5 (DOSSIER-66).

`save_platform_config` ecrivait `telegraf_output_token` TEL QUEL (le commentaire
« Chiffrer le token Telegraf si fourni » etait faux depuis l'origine), et
`_build_agent_config_content` le relisait tel quel. Le PSK Zabbix voisin, lui,
etait chiffre. Le correctif chiffre a l'ecriture ET dechiffre a la relecture —
sans quoi l'agent distant recevrait `gcm:...` et echouerait a s'authentifier.

Les tokens DEJA en base sont en clair : la relecture doit les accepter tels
quels, sinon le prochain deploiement Telegraf casserait.

`conftest.py` remplace `encryption` par un MagicMock (`encrypt_password` rend
'encrypted_password', `decrypt_password` rend 'decrypted_password') : les tests de
route s'appuient sur ces valeurs ; le test d'aller-retour charge le VRAI module.
"""
import importlib.util
from pathlib import Path

import routes.supervision as sup
from tests.conftest import MockCursor

MACHINE = {'id': 2, 'name': 'srv-dev', 'ip': '10.0.0.2'}
TOKEN = 'jeton-influx-EN-CLAIR-123'


def test_la_route_n_ecrit_plus_le_token_en_clair(client, admin_headers, mock_db, monkeypatch):
    ecrites = []
    origine = MockCursor.execute

    def enregistre(self, query, params=None):
        ecrites.append((query, params))
        return origine(self, query, params)

    monkeypatch.setattr(MockCursor, 'execute', enregistre)

    r = client.post('/supervision/config/telegraf', headers=admin_headers,
                    json={'telegraf_output_url': 'https://influx.example', 'telegraf_output_token': TOKEN})

    assert r.status_code == 200, r.get_data(as_text=True)
    parametres = [str(p) for _q, ps in ecrites if ps for p in ps]
    assert not any(TOKEN in p for p in parametres), 'le token part EN CLAIR vers la base'
    assert 'encrypted_password' in parametres, 'le token n est pas passe par encrypt_password'


def test_le_masque_garde_le_token_existant(client, admin_headers, mock_db, monkeypatch):
    ecrites = []
    origine = MockCursor.execute
    monkeypatch.setattr(MockCursor, 'execute',
                        lambda self, q, p=None: (ecrites.append((q, p)), origine(self, q, p))[1])

    client.post('/supervision/config/telegraf', headers=admin_headers,
                json={'telegraf_output_url': 'https://influx.example', 'telegraf_output_token': '********'})

    parametres = [p for _q, ps in ecrites if ps for p in ps]
    assert '********' not in parametres, 'le masque d affichage a ete enregistre comme token'


def test_l_agent_recoit_le_token_dechiffre():
    cfg = {'telegraf_output_url': 'https://influx.example', 'telegraf_output_token': 'gcm:AAAA'}

    contenu = sup._build_agent_config_content('telegraf', cfg, MACHINE)

    assert 'token = "decrypted_password"' in contenu, \
        'l agent recevrait le CHIFFRE et echouerait a s authentifier'
    assert 'gcm:AAAA' not in contenu


def test_un_ancien_token_en_clair_reste_utilisable():
    cfg = {'telegraf_output_url': 'https://influx.example', 'telegraf_output_token': TOKEN}

    contenu = sup._build_agent_config_content('telegraf', cfg, MACHINE)

    assert f'token = "{TOKEN}"' in contenu, 'un token deja en base ne doit pas casser le deploiement'


def test_aller_retour_avec_le_vrai_chiffrement():
    chemin = Path(__file__).resolve().parents[1] / 'encryption.py'
    spec = importlib.util.spec_from_file_location('encryption_reel_telegraf', chemin)
    reel = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reel)
    enc = reel.Encryption()

    stocke = sup._chiffre_token_telegraf(TOKEN, enc)

    assert stocke and stocke != TOKEN and TOKEN not in stocke
    assert sup._dechiffre_token_telegraf(stocke, enc) == TOKEN
    assert sup._dechiffre_token_telegraf(TOKEN, enc) == TOKEN, 'clair historique'
    assert sup._dechiffre_token_telegraf('', enc) == ''
    assert sup._chiffre_token_telegraf('********', enc) is None, 'le masque garde l existant'
    assert sup._chiffre_token_telegraf('', enc) == '', 'vider reste possible'
