"""
test_cve_trends.py - Diagramme "Tendances CVE (30 jours)" du dashboard.

Regression : le diagramme n'affichait qu'un seul point ("le dernier, pas
d'historique"). Deux causes distinctes, corrigees ensemble :

  1. Retention des scans CVE basee sur un NOMBRE (CVE_SCAN_RETENTION=10 par
     machine) au lieu d'une DUREE -> tout l'historique journalier au-dela des
     10 derniers scans etait purge ; avec plusieurs scans le meme jour, les 10
     scans conserves retombaient sur une seule date. (voir test_scheduler.py)

  2. Requete de tendance : `SUM(...) GROUP BY DATE(scan_date)` additionnait
     TOUS les scans d'une meme machine le meme jour -> total journalier gonfle
     des qu'une machine etait scannee plusieurs fois par jour. La requete ne
     doit retenir que le DERNIER scan par (machine, jour) avant de sommer.

Ces tests asservissent la SPEC (comportement attendu), pas l'implementation
figee : fenetre de 30 jours preservee + deduplication (machine, jour).
"""


def _run(client, api_headers):
    return client.get('/cve_trends', headers=api_headers)


class TestCveTrendsEndpoint:
    def test_endpoint_ok(self, client, api_headers, mock_db):
        r = _run(client, api_headers)
        assert r.status_code == 200
        assert r.get_json()['success'] is True

    def test_fenetre_30_jours_preservee(self, client, api_headers, mock_db):
        _run(client, api_headers)
        q = mock_db._cursor._last_query  # deja en minuscules
        assert 'interval 30 day' in q

    def test_dedup_dernier_scan_par_machine_et_par_jour(self, client, api_headers, mock_db):
        _run(client, api_headers)
        q = mock_db._cursor._last_query
        # On ne somme que le dernier scan de chaque (machine, jour).
        assert 'partition by machine_id, date(scan_date)' in q
        assert 'order by scan_date desc' in q
        assert 'where rn = 1' in q

    def test_ne_double_compte_plus_les_scans_intra_journee(self, client, api_headers, mock_db):
        # Spec : le SUM doit s'appliquer a la sous-requete dedupliquee (rn = 1),
        # jamais directement a la table brute (qui double-comptait les scans
        # multiples d'une meme machine le meme jour).
        _run(client, api_headers)
        q = mock_db._cursor._last_query
        idx_sum = q.find('sum(cve_count)')
        idx_rn = q.find('row_number()')
        assert idx_sum != -1 and idx_rn != -1
        # le SUM externe apparait AVANT la sous-requete row_number() (il l'englobe)
        assert idx_sum < idx_rn
