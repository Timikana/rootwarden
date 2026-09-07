"""test_sudo_fail_closed.py - Regression : un echec de rendu ELARGISSAIT le privilege.

Bug corrige le 2026-09-07 (PARITE/E-463, DOSSIER-42). `add_to_sudoers` rendait la
politique via `sudo_manager.render_policy` ; en cas de `ValueError` ou
`ImportError`, la branche `except` posait `policy = None`, ce qui faisait tomber
dans le repli historique et ECRIVAIT :

    <user> ALL=(ALL:ALL) NOPASSWD: ALL

**Plus l'intention etait etroite, plus le resultat etait large** — et precisement
quand quelque chose venait de mal se passer. L'asymetrie etait DANS LA MEME
FONCTION : un username invalide rendait la main sans rien ecrire, une politique
invalide faisait ecrire un acces root sans mot de passe et sans restriction.

Mesure d'avant / apres, executee sur les deux versions du fichier :

    AVANT   rendu en echec -> 3 commande(s), contenu `john ALL=(ALL:ALL) NOPASSWD: ALL`
    APRES   rendu en echec -> 0 commande(s)

⚠ CE FICHIER EXISTE PARCE QUE LES DEUX SUITES QUI COUVRAIENT `add_to_sudoers`
N'EXERCAIENT PAS CE CHEMIN : `grep -cE 'ValueError|side_effect|raise'` rendait
**0** sur `test_sudoers_naming.py` et `test_visudo_legacy_echo.py`. Leurs verts
ne disaient rien du defaut, et rien ne mordrait si quelqu'un remettait le repli.

Spec attendue :
  - sur le chemin du RENDU EN ECHEC, la fonction n'envoie AUCUNE commande ;
  - l'assertion porte sur « RIEN n'est ecrit », pas sur « pas de NOPASSWD ALL » :
    la seconde passerait A VIDE si le repli revenait avec un autre contenu ;
  - ⚠ un TEMOIN POSITIF exige que le chemin NOMINAL envoie des commandes, sans
    quoi le test passerait aussi si la fonction ne faisait plus rien du tout —
    donc si l'on retirait l'`except`, ou si l'on cassait la fonction entiere ;
  - ⚠ le chemin `elif sudo:` de l'appelant (booleen `users.sudo = 1`, appel SANS
    argument `policy`) ECRIT TOUJOURS, et c'est DELIBERE : ce que doit signifier
    `users.sudo = 1` sans politique par machine est une question ouverte, non
    tranchee. Ce test la protege d'etre tranchee par accident.

L'`except` de la fonction reste ETROIT — `(ValueError, ImportError)`. Un
`TypeError` ou un `KeyError` de `render_policy` s'echappe toujours, par choix de
l'exploitant. Ce fichier ne couvre donc pas ces deux types.

Aucun exercice reel : `execute_command_as_root` est instrumentee et `channel` vaut
`None`. Un sudoers invalide casse `sudo` sur toute la machine — on instrumente,
on ne joint pas.
"""
import pytest

import configure_servers as cs
import sudo_manager

POLICY_VALIDE = {'preset': 'all_nopasswd', 'nopasswd': True}


def _mouchard(monkeypatch):
    """Remplace `execute_command_as_root` et rend la liste des commandes emises."""
    commandes = []

    def faux_exec(channel, command, logger=None, **kw):
        commandes.append(command)
        # Sortie qui satisfait les controles positifs de la fonction (visudo OK,
        # installation confirmee) : on mesure ce qui est ENVOYE, pas la reaction
        # a un echec distant.
        return f"{command}\r\n__VISUDO_OK__\r\n__INSTALL_OK__\r\n"

    monkeypatch.setattr(cs, 'execute_command_as_root', faux_exec)

    return commandes


def _rendu_qui_leve(monkeypatch, exception):
    def boum(policy):
        raise exception

    monkeypatch.setattr(sudo_manager, 'render_policy', boum)


class TestUnEchecDeRenduNElargitPas:
    @pytest.mark.parametrize('exception', [ValueError('preset inconnu'),
                                           ImportError('sudo_manager indisponible')])
    def test_le_rendu_en_echec_n_ecrit_RIEN(self, monkeypatch, exception):
        commandes = _mouchard(monkeypatch)
        _rendu_qui_leve(monkeypatch, exception)

        cs.add_to_sudoers(None, 'john', policy={'preset': 'un_preset_qui_nexiste_pas'})

        # ⚠ « RIEN n'est ecrit », et non « pas de NOPASSWD ALL » : un repli qui
        # reviendrait avec un AUTRE contenu passerait sous la seconde forme.
        assert commandes == [], (
            'un rendu en echec ne doit envoyer AUCUNE commande ; '
            f'{len(commandes)} envoyee(s) : {commandes!r}'
        )

    def test_TEMOIN_POSITIF_le_chemin_nominal_ecrit(self, monkeypatch):
        """Sans ce temoin, le test ci-dessus passerait AUSSI sur une fonction morte.

        C'est la propriete que la session 7 a ajoutee : un garde qui ne peut pas
        mordre est indiscernable d'un garde casse.
        """
        commandes = _mouchard(monkeypatch)

        cs.add_to_sudoers(None, 'john', policy=POLICY_VALIDE)

        assert commandes, (
            "le chemin nominal doit envoyer des commandes ; s'il n'en envoie "
            'aucune, l\'assertion « 0 commande » ci-dessus ne mesure plus rien'
        )

    def test_le_chemin_users_sudo_ECRIT_TOUJOURS(self, monkeypatch):
        """`elif sudo:` chez l'appelant : appel SANS argument `policy`.

        Ce chemin atteint le meme repli, et il ECRIT — deliberement. Ce que doit
        signifier `users.sudo = 1` sans politique par machine est une question
        ouverte : toute reponse autre que « tout » retirerait du sudo a des
        comptes qui en ont aujourd'hui. **Ce test empeche qu'elle soit tranchee
        depuis un test plutot que par une decision.**
        """
        commandes = _mouchard(monkeypatch)

        cs.add_to_sudoers(None, 'john')

        assert commandes, (
            'le chemin `users.sudo = 1` doit continuer a ecrire : le corriger '
            'est une decision, pas un effet de bord du correctif fail-closed'
        )

    def test_un_username_invalide_n_ecrivait_DEJA_rien(self, monkeypatch):
        """L'ancre de l'asymetrie : ce chemin rendait la main avant le correctif.

        Il est asserte ici pour que la comparaison reste lisible — c'est de LUI
        que le correctif tire sa forme.
        """
        commandes = _mouchard(monkeypatch)

        cs.add_to_sudoers(None, '../etc/passwd', policy=POLICY_VALIDE)

        assert commandes == [], f'un username invalide ne doit rien envoyer : {commandes!r}'
