"""
test_tickets.py - Ticketing ITSM (v1.33) : gating de role + dedup (source, ref, machine_id).

Sans provider configure (TICKETING_ENABLED off), un ticket est trace en 'local'.
La dedup evite de recreer un ticket pour un finding deja pousse.
"""


class TestTicketGating:
    def test_post_refuse_role1(self, client, user_headers, mock_db):
        resp = client.post('/tickets', headers=user_headers,
                           json={'summary': 'x', 'description': 'y'})
        assert resp.status_code == 403

    def test_post_summary_requis(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.post('/tickets', headers=admin_headers, json={'source': 'manual'})
        assert resp.status_code == 400

    def test_get_liste_ok(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []
        resp = client.get('/tickets', headers=admin_headers)
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True


class TestTicketDedup:
    def test_dedup_hit_retourne_existant(self, client, admin_headers, mock_cursor):
        # un ticket existe deja pour (source, ref, machine_id) -> deduped, pas de creation
        mock_cursor._results = [{'id': 42, 'provider': 'jira'}]
        resp = client.post('/tickets', headers=admin_headers,
                           json={'source': 'cve', 'ref': 'CVE-2026-1', 'machine_id': 2,
                                 'summary': 'CVE-2026-1'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['deduped'] is True
        assert data['id'] == 42
        assert data['provider'] == 'jira'

    def test_dedup_miss_cree_ticket_local(self, client, admin_headers, mock_cursor):
        # aucun ticket existant + provider desactive -> ticket 'local', deduped=False
        mock_cursor._results = []
        resp = client.post('/tickets', headers=admin_headers,
                           json={'source': 'cve', 'ref': 'CVE-2026-2', 'machine_id': 2,
                                 'summary': 'CVE-2026-2'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['deduped'] is False
        assert data['provider'] == 'local'

    def test_source_cve_summary_auto(self, client, admin_headers, mock_cursor):
        # source=cve + ref sans summary -> summary genere automatiquement (pas de 400)
        mock_cursor._results = []
        resp = client.post('/tickets', headers=admin_headers,
                           json={'source': 'cve', 'ref': 'CVE-2026-3', 'machine_id': 2})
        assert resp.status_code == 200
