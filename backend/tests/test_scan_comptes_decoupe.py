"""
test_scan_comptes_decoupe.py - Les deux etapes PURES extraites de
`scan_server_users` (2026-11-16) : la lecture de `/etc/passwd` en comptes, et le
classement d'un compte vu pour la premiere fois.

Jusqu'ici elles n'etaient atteignables qu'a travers la route entiere, avec une
session SSH et une base simulees. Le decoupage les rend testables seules ; le
comportement de la route, lui, a ete compare avant et apres sur le serveur SSH
de banc (reponses et base identiques, purge des cles comprise).
"""
from routes.ssh import _classement_automatique, _comptes_scannes

PASSWD = (
    "root:0:/root:/bin/bash\n"
    "daemon:1:/usr/sbin:/usr/sbin/nologin\n"
    "alice:1001:/home/alice:/bin/bash\n"
    "\n"
    "tronquee:1002\n"
    "evasion:1003:/home/a b:/bin/bash\n"
    "bob:abc:/home/bob:/bin/sh\n"
)


def test_comptes_lus_et_lignes_ecartees():
    comptes = _comptes_scannes(PASSWD, {}, '')
    noms = [c['name'] for c in comptes]
    # ligne vide, ligne tronquee et home hors motif sont ecartees
    assert noms == ['root', 'daemon', 'alice', 'bob']
    # un uid non numerique vaut 0, comme avant le decoupage
    assert next(c for c in comptes if c['name'] == 'bob')['uid'] == 0


def test_cles_et_cle_de_plateforme():
    cles = {'alice': [{'data': 'AAAAplateforme', 'fingerprint': 'f1'},
                      {'data': 'AAAAautre', 'fingerprint': 'f2'}]}
    alice = next(c for c in _comptes_scannes(PASSWD, cles, 'plateforme') if c['name'] == 'alice')
    assert alice['keys_count'] == 2
    assert alice['has_platform_key'] is True
    assert [k['is_platform'] for k in alice['keys']] == [True, False]


def test_sans_fragment_de_plateforme_aucune_cle_n_est_la_sienne():
    # Temoin du test precedent : un fragment vide ne marque rien.
    cles = {'alice': [{'data': 'AAAAplateforme', 'fingerprint': 'f1'}]}
    alice = next(c for c in _comptes_scannes(PASSWD, cles, '') if c['name'] == 'alice')
    assert alice['has_platform_key'] is False


def test_classement_automatique():
    sys_users = {'root', 'deploy'}
    rw = {'alice'}
    c = lambda nom, shell='/bin/bash': _classement_automatique(
        {'name': nom, 'shell': shell}, sys_users, rw)
    assert c('root') == ('excluded', 'manual', 'Compte systeme (auto-classifie)')
    assert c('ROOT')[0] == 'excluded'                       # casse ignoree cote systeme
    assert c('svc', '/usr/sbin/nologin') == (
        'excluded', 'manual', 'Compte sans login (shell=/usr/sbin/nologin) - auto-classifie')
    assert c('alice') == ('managed', 'rootwarden', 'Utilisateur RootWarden (auto-classifie)')
    assert c('carol') == ('pending_review', None, None)
    # le compte systeme l'emporte sur l'autorisation RootWarden
    assert _classement_automatique({'name': 'deploy', 'shell': '/bin/bash'},
                                   sys_users, {'deploy'})[0] == 'excluded'
