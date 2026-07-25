"""
test_search.py - Recherche globale (v1.34) : gating + terme borne + LIKE parametre.

La recherche traverse users + audit -> reservee admin (role 2 + can_admin_portal).
Terme < 2 caracteres => resultats vides (anti-scan). LIKE 100% parametre (pas
d'injection possible via q).
"""


class TestSearchGating:
    def test_refuse_role1(self, client, user_headers, mock_db):
        resp = client.get('/search?q=srv', headers=user_headers)
        assert resp.status_code == 403

    def test_sans_api_key(self, client):
        resp = client.get('/search?q=srv')
        assert resp.status_code == 401


class TestSearchBehaviour:
    def test_terme_trop_court_resultats_vides(self, client, admin_headers, mock_db):
        resp = client.get('/search?q=a', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['total'] == 0
        assert data['results'] == {}

    def test_terme_valide_structure(self, client, admin_headers, mock_cursor):
        mock_cursor._results = []  # aucune donnee -> categories vides mais presentes
        resp = client.get('/search?q=srv', headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        for cat in ('machines', 'users', 'cves', 'tickets', 'audit'):
            assert cat in data['results'], f'categorie {cat} absente'

    def test_injection_like_ne_casse_pas(self, client, admin_headers, mock_cursor):
        # LIKE parametre : un payload SQL dans q ne doit pas provoquer d'erreur 500
        mock_cursor._results = []
        resp = client.get("/search", headers=admin_headers, query_string={'q': "' OR 1=1 --"})
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True
