r"""
test_updates_paquets.py - Le `$` d'une regex python accepte un `\n` FINAL, et
`_validate_package_list` employait `.match()`.

┌─ CE QU'ETAIT LE DEFAUT ──────────────────────────────────────────────────────┐
│ `_SAFE_PKG` vaut `^[a-zA-Z0-9][a-zA-Z0-9.+_\-]*$` — ancre aux DEUX bouts, et  │
│ pourtant `re.match('nginx\n')` REND UN MATCH : en python, `$` s'apparie aussi │
│ juste avant un saut de ligne terminal. Le filtre CONSERVAIT donc le nom avec  │
│ son `\n`, et contrairement a `_validate_username` du `sudo_manager` il n'y a  │
│ ici AUCUN `.strip()` pour le rattraper.                                       │
│                                                                               │
│ POST /custom_update  {"selected_packages": ["nginx\n", "reboot"]}             │
│   les DEUX passaient, `' '.join(...)` rendait "nginx\n reboot", interpole     │
│   dans f"{env_prefix} && apt-get install -y ... {pkg_str}" :                  │
│     [0] export ... && apt-get install -y nginx                                │
│     [1]  reboot          <- LIGNE SEPAREE, EXECUTEE EN ROOT                    │
│   Meme mecanisme sur `hold_cmd` / `unhold_cmd` (apt-mark hold/unhold).        │
└──────────────────────────────────────────────────────────────────────────────┘

BORNES, mesurees et non supposees : la seconde entree doit elle-meme passer le
motif, donc PAS d'espace, PAS d'argument, PAS de `;`. La charge est UNE commande
NUE (`id`, `reboot`, `poweroff`, `halt`, `sync`, `nc` passent ; `rm -rf /`,
`curl http://x`, `sh -c id` non). Et la route exige `require_api_key` +
`can_update_linux` + `require_machine_access` : c'est une ELEVATION depuis
« peut mettre a jour des paquets », pas une RCE non authentifiee.

`fullmatch` ferme la classe PAR CONSTRUCTION : il refuse tout `\n` final sans
dependre d'un `.strip()` place au bon endroit. C'est la meme famille que E-174
(`test_fail2ban_manager.py`), ou un identifiant de portee IPv6 atteignait une
commande root.
"""

from routes.updates import _validate_package_list


class TestSautDeLigneFinal:
    def test_un_nom_a_saut_de_ligne_final_est_ECARTE(self):
        # `.match()` le gardait ; `.fullmatch()` le refuse.
        assert _validate_package_list(['nginx\n']) == []

    def test_le_saut_de_ligne_n_injecte_plus_de_seconde_commande(self):
        garde = _validate_package_list(['nginx\n', 'reboot'])
        assert 'nginx\n' not in garde
        assert not any('\n' in p for p in garde)

    def test_aucune_valeur_RETENUE_ne_porte_de_metacaractere(self):
        """La propriete qui compte n'est pas « la liste est courte » mais
        « rien de ce qui SORT ne peut couper une commande »."""
        entrees = ['nginx', 'nginx\n', 'a; id', 'a && id', '$(id)', '`id`',
                   'a|b', '../x', '', 'a\nb', 'a\r', 'a\r\n', 'a\tb', 'a b']
        for p in _validate_package_list(entrees):
            assert not any(c in p for c in ' ;|&$`\n\r\t<>()'), p


class TestNomsLegitimes:
    """Un correctif qui refuse aussi le legitime deplace le defaut, il ne le
    corrige pas. Le TEMOIN de ce fichier est ici : sans lui, un validateur qui
    rend TOUJOURS la liste vide passerait la classe ci-dessus."""

    def test_les_noms_apt_usuels_passent_TOUS(self):
        noms = ['nginx', 'apache2', 'python3.13', 'lib32z1', 'g++',
                'linux-image-amd64', 'openssh-server', 'php8.4-fpm',
                'libssl3', 'ca-certificates', 'zlib1g-dev']
        assert _validate_package_list(noms) == noms

    def test_les_non_chaines_sont_ecartees(self):
        assert _validate_package_list([None, 42, ['nginx'], {'a': 1}]) == []

    def test_une_liste_vide_rend_une_liste_vide(self):
        assert _validate_package_list([]) == []
