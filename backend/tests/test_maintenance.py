"""
test_maintenance.py - Tests unitaires de la logique des fenetres de maintenance (v1.29).

Complement rapide (CI) du test d'integration E2E 07-maintenance : ici on teste
is_allowed() en pur, en injectant `now` et en mockant la requete DB des fenetres.
"""
from datetime import datetime, time as dtime

import pytest

import maintenance as mw

# Lundi 12:00 (weekday()==0)
MONDAY_NOON = datetime(2026, 7, 20, 12, 0, 0)


class TestIsAllowed:
    def test_superadmin_bypass_sans_db(self):
        # role 3 -> autorise sans meme toucher la DB
        allowed, reason = mw.is_allowed(2, role=3, now=MONDAY_NOON)
        assert allowed is True
        assert reason == 'superadmin-bypass'

    def test_aucune_fenetre_autorise(self, mock_cursor):
        mock_cursor._results = []  # aucune fenetre active
        allowed, reason = mw.is_allowed(2, role=1, now=MONDAY_NOON)
        assert allowed is True
        assert reason == 'no-window'

    def test_dans_la_fenetre_autorise(self, mock_cursor):
        mock_cursor._results = [
            {'days': '0,1,2,3,4,5,6', 'start_time': dtime(0, 0), 'end_time': dtime(23, 59)},
        ]
        allowed, reason = mw.is_allowed(2, role=1, now=MONDAY_NOON)
        assert allowed is True
        assert reason == 'in-window'

    def test_hors_fenetre_bloque(self, mock_cursor):
        # fenetre le mardi (weekday 1) uniquement ; on est lundi -> bloque
        mock_cursor._results = [
            {'days': '1', 'start_time': dtime(0, 0), 'end_time': dtime(23, 59)},
        ]
        allowed, reason = mw.is_allowed(2, role=1, now=MONDAY_NOON)
        assert allowed is False
        assert reason == 'outside-window'

    def test_bon_jour_mais_hors_plage_horaire(self, mock_cursor):
        # lundi mais fenetre 01:00-02:00, il est 12:00 -> bloque
        mock_cursor._results = [
            {'days': '0', 'start_time': dtime(1, 0), 'end_time': dtime(2, 0)},
        ]
        allowed, reason = mw.is_allowed(2, role=1, now=MONDAY_NOON)
        assert allowed is False
        assert reason == 'outside-window'

    def test_fenetre_a_cheval_sur_minuit(self, mock_cursor):
        # fenetre 22:00 -> 06:00. A 12:00 un lundi -> hors fenetre.
        mock_cursor._results = [
            {'days': '0', 'start_time': dtime(22, 0), 'end_time': dtime(6, 0)},
        ]
        assert mw.is_allowed(2, role=1, now=MONDAY_NOON)[0] is False
        # a 23:00 le meme lundi -> dans la fenetre nocturne
        assert mw.is_allowed(2, role=1, now=MONDAY_NOON.replace(hour=23))[1] == 'in-window'


class TestInWindowHelpers:
    def test_parse_days(self):
        assert mw._parse_days('0,1,6') == {0, 1, 6}
        assert mw._parse_days('') == set()
        assert mw._parse_days('9,abc,3') == {3}  # hors bornes / non numerique ignore

    def test_in_window_jour_simple(self):
        # lundi=0, plage 08:00-18:00
        assert mw._in_window(MONDAY_NOON, 0, {0}, dtime(8, 0), dtime(18, 0)) is True
        assert mw._in_window(MONDAY_NOON, 0, {2}, dtime(8, 0), dtime(18, 0)) is False
