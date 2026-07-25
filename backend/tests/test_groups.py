"""
test_groups.py - Groupes de machines (v1.28) : whitelist de filtres + actions de masse.

_sanitize_filters est la defense A03 : seules des colonnes/valeurs whitelistees
entrent dans la resolution dynamique (aucune cle/valeur arbitraire dans le SQL).
"""
from routes.groups import _sanitize_filters, _FILTER_ENUMS, _BULK_ACTIONS


class TestSanitizeFilters:
    def test_garde_colonnes_et_valeurs_valides(self):
        out = _sanitize_filters({'environment': ['PROD', 'DEV'], 'criticality': ['CRITIQUE']})
        assert out == {'environment': ['PROD', 'DEV'], 'criticality': ['CRITIQUE']}

    def test_drop_valeurs_hors_whitelist(self):
        # 'HACK' n'est pas une valeur d'environment autorisee -> filtree
        out = _sanitize_filters({'environment': ['PROD', 'HACK', 'DROP TABLE']})
        assert out == {'environment': ['PROD']}

    def test_drop_colonnes_inconnues(self):
        # une colonne non whitelistee (tentative d'injection de colonne) est ignoree
        out = _sanitize_filters({'id; DROP TABLE machines': ['x'], 'password': ['y']})
        assert out == {}

    def test_non_dict_retourne_vide(self):
        assert _sanitize_filters('not a dict') == {}
        assert _sanitize_filters(None) == {}
        assert _sanitize_filters(['list']) == {}

    def test_tags_bornes_a_50_chars(self):
        out = _sanitize_filters({'tags': ['prod', 'x' * 80, '', '  ']})
        assert 'tags' in out
        assert 'prod' in out['tags']
        assert all(len(t) <= 50 for t in out['tags'])

    def test_valeur_non_liste_ignoree(self):
        # environment='PROD' (str au lieu de liste) -> ignore (on attend une liste)
        out = _sanitize_filters({'environment': 'PROD'})
        assert out == {}


class TestGroupRoutes:
    def test_run_action_inconnue_400(self, client, admin_headers, mock_cursor):
        mock_cursor._results = [{'id': 1, 'group_type': 'static', 'filters': None}]
        resp = client.post('/groups/1/run', headers=admin_headers, json={'action': 'rm_rf'})
        assert resp.status_code == 400

    def test_create_sans_nom_400(self, client, admin_headers, mock_db):
        resp = client.post('/groups', headers=admin_headers, json={'group_type': 'dynamic'})
        assert resp.status_code == 400

    def test_list_refuse_role1(self, client, user_headers, mock_db):
        resp = client.get('/groups', headers=user_headers)
        assert resp.status_code == 403
