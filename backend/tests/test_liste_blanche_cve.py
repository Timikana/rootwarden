"""La liste blanche CVE agit : elle etait ecrite et lue par personne."""

from unittest.mock import patch

import liste_blanche_cve as lb


class _Cur:
    def __init__(self, lignes=None):
        self.lignes = lignes or []
        self.requetes = []
        self.lastrowid = 42

    def execute(self, sql, params=None):
        self.requetes.append((' '.join(str(sql).split()), params))

    def fetchall(self):
        return self.lignes


class _Conn:
    def __init__(self, cur):
        self.cur = cur

    def cursor(self, *a, **k):
        return self.cur

    def commit(self):
        pass

    def close(self):
        pass


def test_lit_les_entrees_globales_et_de_la_machine_non_expirees():
    cur = _Cur([('cve-2026-0001',), ('CVE-2026-0002',)])
    with patch('mysql.connector.connect', return_value=_Conn(cur)):
        assert lb.cves_blanchies(7) == {'CVE-2026-0001', 'CVE-2026-0002'}
    sql, params = cur.requetes[0]
    assert 'machine_id IS NULL OR machine_id = %s' in sql
    assert 'expires_at IS NULL OR expires_at >= CURDATE()' in sql
    assert params == (7,)


def test_une_panne_ne_fait_taire_aucune_alerte():
    with patch('mysql.connector.connect', side_effect=RuntimeError('base injoignable')):
        assert lb.cves_blanchies(7) == set()


def test_marque_et_actifs():
    findings = [{'cve_id': 'CVE-1'}, {'cve_id': 'cve-2'}, {'cve_id': 'CVE-3'}]
    assert lb.marque(findings, {'CVE-2'}) == 1
    assert [f['cve_id'] for f in lb.actifs(findings)] == ['CVE-1', 'CVE-3']


def test_le_scan_ecrit_toutes_les_lignes_mais_ne_compte_pas_les_blanchies():
    # conftest.py remplace `cve_scanner` par un MagicMock : sans charger le VRAI
    # fichier, ce test appellerait une doublure et ne mesurerait rien.
    import importlib.util
    import pathlib as _p
    spec = importlib.util.spec_from_file_location(
        'cve_scanner_reel', _p.Path(__file__).resolve().parent.parent / 'cve_scanner.py')
    cve_scanner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cve_scanner)
    findings = [
        {'package': 'p', 'version': '1', 'cve_id': 'CVE-A', 'cvss': 9.8, 'severity': 'CRITICAL', 'blanchie': True},
        {'package': 'p', 'version': '1', 'cve_id': 'CVE-B', 'cvss': 9.1, 'severity': 'CRITICAL'},
        {'package': 'p', 'version': '1', 'cve_id': 'CVE-C', 'cvss': 7.5, 'severity': 'HIGH', 'blanchie': True},
    ]
    cur = _Cur()
    with patch.object(cve_scanner.mysql.connector, 'connect', return_value=_Conn(cur)):
        cve_scanner._save_scan(3, findings, 120, 7.0)
    scans = [p for s, p in cur.requetes if s.startswith('INSERT INTO cve_scans')]
    lignes = [p for s, p in cur.requetes if s.startswith('INSERT INTO cve_findings')]
    assert scans, f'aucune insertion de scan capturee : {[s[:60] for s, _ in cur.requetes]}'
    # (machine, paquets, cve_count, critical, high, medium, low, min_cvss)
    assert scans[0][2:7] == (1, 1, 0, 0, 0)
    assert len(lignes) == 3
