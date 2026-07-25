"""
test_chatops.py - Tests unitaires du module ChatOps entrant (v1.32).

/chatops/command est le SEUL endpoint public (avec /test) : son authentification
repose entierement sur la signature Slack v0 (HMAC-SHA256 + anti-rejeu 5 min) ou un
jeton partage constant-time. Plus le gate de role (correctif A01 v1.37.1) : un compte
chat mappe en role 1 ne doit PAS pouvoir approuver/rejeter du 4-eyes.

Logique pure (crypto + routage) : aucune I/O reelle (resolve_user/_decide mockes).
"""
import time
import hmac
import hashlib

import pytest

import chatops


def _sign(secret, timestamp, body):
    base = f"v0:{timestamp}:{body}".encode('utf-8')
    return 'v0=' + hmac.new(secret.encode('utf-8'), base, hashlib.sha256).hexdigest()


@pytest.fixture
def slack_secret(monkeypatch):
    secret = 'test_signing_secret_123'
    monkeypatch.setattr(chatops.Config, 'CHATOPS_SLACK_SIGNING_SECRET', secret, raising=False)
    return secret


class TestSlackSignature:
    def test_valid_signature_accepted(self, slack_secret):
        ts = str(int(time.time()))
        body = 'text=status&user_id=U123'
        sig = _sign(slack_secret, ts, body)
        assert chatops.verify_slack_signature(ts, body, sig) is True

    def test_tampered_body_rejected(self, slack_secret):
        ts = str(int(time.time()))
        sig = _sign(slack_secret, ts, 'text=status')
        assert chatops.verify_slack_signature(ts, 'text=reboot', sig) is False

    def test_wrong_secret_rejected(self, slack_secret):
        ts = str(int(time.time()))
        body = 'text=status'
        sig = _sign('other_secret', ts, body)
        assert chatops.verify_slack_signature(ts, body, sig) is False

    def test_expired_timestamp_rejected(self, slack_secret):
        # signature valide mais horodatage vieux de > 5 min -> anti-rejeu
        ts = str(int(time.time()) - 400)
        body = 'text=status'
        sig = _sign(slack_secret, ts, body)
        assert chatops.verify_slack_signature(ts, body, sig) is False

    def test_missing_parts_rejected(self, slack_secret):
        assert chatops.verify_slack_signature('', 'b', 'sig') is False
        assert chatops.verify_slack_signature(str(int(time.time())), 'b', '') is False

    def test_no_secret_configured_rejects(self, monkeypatch):
        monkeypatch.setattr(chatops.Config, 'CHATOPS_SLACK_SIGNING_SECRET', '', raising=False)
        ts = str(int(time.time()))
        assert chatops.verify_slack_signature(ts, 'b', _sign('x', ts, 'b')) is False


class TestSharedToken:
    def test_valid_token(self, monkeypatch):
        monkeypatch.setattr(chatops.Config, 'CHATOPS_TOKEN', 'sekret', raising=False)
        assert chatops.verify_token('sekret') is True

    def test_wrong_token(self, monkeypatch):
        monkeypatch.setattr(chatops.Config, 'CHATOPS_TOKEN', 'sekret', raising=False)
        assert chatops.verify_token('nope') is False

    def test_empty_config_rejects(self, monkeypatch):
        monkeypatch.setattr(chatops.Config, 'CHATOPS_TOKEN', '', raising=False)
        assert chatops.verify_token('anything') is False


class TestDispatchRoleGate:
    """Correctif A01 (v1.37.1) : approve/reject reserve au role >= 2."""

    def test_help_needs_no_user(self):
        out = chatops.dispatch('help', 'Uxxx')
        assert 'Commandes ChatOps' in out

    def test_unmapped_user_refused(self, monkeypatch):
        monkeypatch.setattr(chatops, 'resolve_user', lambda cu, p='slack': (None, None, None))
        out = chatops.dispatch('status', 'Uxxx')
        assert 'pas associe' in out.lower() or 'lock' in out.lower()

    def test_approve_role1_refused(self, monkeypatch):
        # compte chat mappe en role 1 : ne doit PAS pouvoir approuver
        monkeypatch.setattr(chatops, 'resolve_user', lambda cu, p='slack': (5, 1, 'ops'))
        called = {'decide': False}
        monkeypatch.setattr(chatops, '_decide', lambda *a, **k: called.__setitem__('decide', True) or 'X')
        out = chatops.dispatch('approve 3', 'Uops')
        assert 'reserve' in out.lower() or 'insuffisant' in out.lower()
        assert called['decide'] is False, "_decide ne doit pas etre appele pour un role 1"

    def test_approve_role2_reaches_decide(self, monkeypatch):
        monkeypatch.setattr(chatops, 'resolve_user', lambda cu, p='slack': (7, 2, 'admin'))
        monkeypatch.setattr(chatops, '_decide', lambda rid, dec, aid, ar: f'DECIDED:{dec}:{aid}')
        out = chatops.dispatch('approve 3', 'Uadmin')
        assert out == 'DECIDED:approved:7'

    def test_reject_role2_reaches_decide(self, monkeypatch):
        monkeypatch.setattr(chatops, 'resolve_user', lambda cu, p='slack': (7, 2, 'admin'))
        monkeypatch.setattr(chatops, '_decide', lambda rid, dec, aid, ar: f'DECIDED:{dec}')
        out = chatops.dispatch('reject 9 trop risque', 'Uadmin')
        assert out == 'DECIDED:rejected'
