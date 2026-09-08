r"""
test_ssh_audit_sauvegardes.py - Ce que le producteur ECRIT, le validateur doit
l'ACCEPTER.

┌─ CE QU'ETAIT LE DEFAUT ──────────────────────────────────────────────────────┐
│ `backup_sshd_config` produit `sshd_config.bak.%Y%m%d_%H%M%S` — HUIT chiffres, │
│ un souligne, SIX chiffres. `_BACKUP_NAME_RE` exigeait                         │
│ `^sshd_config\.bak\.\d{14}$` — QUATORZE chiffres, sans souligne.              │
│                                                                               │
│   produit   sshd_config.bak.20260909_003720                                   │
│   accepte   sshd_config.bak.20260909003720                                    │
│   verdict   REFUSE                                                            │
│                                                                               │
│ `restore_backup` rendait donc « Invalid backup name » pour CHAQUE sauvegarde   │
│ reelle — et la route de listage les AFFICHE. L'interface montrait des          │
│ sauvegardes qu'on ne pouvait jamais restaurer : le chemin de repli d'un        │
│ `sshd_config` casse etait mort.                                               │
└──────────────────────────────────────────────────────────────────────────────┘

CE N'ETAIT PAS UNE REGRESSION. Mesure du 2026-09-09 sur l'historique entier du
fichier : six commits le touchent, TOUS avec `strftime('%Y%m%d_%H%M%S')`, depuis
`9e85bfdb` (2026-04-10). Le validateur a ete ajoute PLUS TARD (`1df4aca4`),
contre un format qui n'a jamais existe.

POURQUOI RIEN NE LE SIGNALAIT : un garde qui refuse TOUT rend la meme sortie
qu'un garde correct sur une entree invalide. Le seul test qui l'aurait vu est
celui-ci — l'ALLER-RETOUR — et il n'existait pas. Le correctif n'est donc pas
« un motif plus juste » mais un LIEN entre les deux bouts : le format est
desormais une constante partagee, et ce fichier asserte que les deux s'accordent.
"""

import datetime
import re

from ssh_audit import _BACKUP_NAME_RE, _BACKUP_TS_FORMAT


def _nom_produit(quand=None):
    """Reproduit EXACTEMENT ce que fait `backup_sshd_config`, en derivant du
    meme format — pas en recopiant la chaine."""
    quand = quand or datetime.datetime.now()
    return f"sshd_config.bak.{quand.strftime(_BACKUP_TS_FORMAT)}"


class TestAllerRetour:
    def test_le_nom_PRODUIT_est_accepte_par_le_validateur(self):
        nom = _nom_produit()
        assert _BACKUP_NAME_RE.fullmatch(nom), (
            f"{nom!r} est ce que `backup_sshd_config` ecrit, et "
            f"`_BACKUP_NAME_RE` ({_BACKUP_NAME_RE.pattern}) le refuse : la "
            "restauration est impossible."
        )

    def test_l_aller_retour_tient_sur_des_dates_VARIEES(self):
        """Un seul horodatage pourrait passer par chance — un `01` en tete de
        mois, un `31`, une annee bissextile, minuit et 23:59:59."""
        for q in [
            datetime.datetime(2026, 1, 1, 0, 0, 0),
            datetime.datetime(2026, 12, 31, 23, 59, 59),
            datetime.datetime(2024, 2, 29, 12, 0, 0),
            datetime.datetime(2026, 9, 9, 0, 3, 7),
        ]:
            nom = _nom_produit(q)
            assert _BACKUP_NAME_RE.fullmatch(nom), nom


class TestLeValidateurREFUSE:
    """Le TEMOIN. Un validateur qui accepte tout passerait la classe ci-dessus
    sans rien garder — et c'est un garde ANTI-TRAVERSEE."""

    def test_la_traversee_de_chemin_est_refusee(self):
        for v in ['../../etc/passwd', '/etc/passwd', 'sshd_config.bak.../x',
                  '../sshd_config.bak.20260909_003720']:
            assert not _BACKUP_NAME_RE.fullmatch(v), v

    def test_l_injection_de_commande_est_refusee(self):
        base = _nom_produit(datetime.datetime(2026, 9, 9, 0, 37, 20))
        for suffixe in ['; id', ' && id', '|id', '$(id)', '`id`', ' ', '\n']:
            assert not _BACKUP_NAME_RE.fullmatch(base + suffixe), suffixe

    def test_le_saut_de_ligne_FINAL_est_refuse(self):
        """`fullmatch` et non `match` : le `$` de python accepte un `\n` final,
        et ce nom part dans un `cp {backup_path} /etc/ssh/sshd_config`."""
        assert not _BACKUP_NAME_RE.fullmatch(_nom_produit() + '\n')

    def test_les_formes_tronquees_sont_refusees(self):
        for v in ['sshd_config', 'sshd_config.bak.', 'sshd_config.bak.2026',
                  'sshd_config.bak.20260909_00372', '', 'sshd_config.bak._']:
            assert not _BACKUP_NAME_RE.fullmatch(v), v

    def test_l_ANCIEN_format_a_14_chiffres_est_refuse(self):
        """Il n'a jamais ete produit : l'accepter serait une permissivite morte
        sur un garde anti-traversee."""
        assert not _BACKUP_NAME_RE.fullmatch('sshd_config.bak.20260909003720')


class TestLaConstanteEstBIENPARTAGEE:
    def test_le_producteur_lit_la_constante_et_non_un_litteral(self):
        """Si quelqu'un recopiait le format dans `backup_sshd_config`, les deux
        bouts pourraient rediverger sans que l'aller-retour ci-dessus tombe."""
        import inspect

        import ssh_audit
        src = inspect.getsource(ssh_audit.backup_sshd_config)
        assert '_BACKUP_TS_FORMAT' in src, src
        assert re.search(r"strftime\(\s*'%", src) is None, (
            "le format est recopie en dur dans le producteur : les deux bouts "
            "peuvent rediverger."
        )
