"""
test_supervision_uninstall.py - La desinstallation ne peut plus annoncer un
succes qu'elle n'a pas verifie, et le rollback n'est plus desarme.

CE QUI ETAIT MESURE AVANT LES CORRECTIFS (2026-08-23, PARITE.md E-88 et E-83).

  1. Les quatre commandes de desinstallation finissaient CHACUNE par `|| true`
     et jetaient leur stderr : la chaine ne pouvait pas sortir autrement qu'en 0.
     Puis `SUCCESS_MACHINE::` etait emis et `_remove_agent` appele
     INCONDITIONNELLEMENT. Mesure : « Agent Zabbix desinstalle » sur une machine
     ou il n'avait JAMAIS ete installe, inventaire passe de 1 a 0 ligne.

  2. `apt-get autoremove -y` figurait dans les quatre : il retire tout paquet que
     le systeme juge devenu inutile, pas seulement les dependances de l'agent.

  3. `_backup_agent_config` faisait `test -f X && cp X Y || echo 'NO_FILE'`, ou
     un `cp` en echec est INDISCERNABLE d'un fichier absent (meme sortie, meme
     rc=0). La fonction rendait `None`, et le repli garde par `if backup_path:`
     etait desarme au moment precis ou il servait.

SPEC ATTENDUE :
  - la commande ne contient plus `autoremove`, et ne purge que ce qui est
    REELLEMENT installe (`dpkg-query`), parce que `apt-get purge` rend 100 quand
    le paquet n'est pas dans l'index du depot — pas seulement quand il n'est pas
    installe (mesure) ;
  - `systemctl stop` reste tolerant : un service deja arrete n'est pas un echec ;
  - code 0 -> l'inventaire est vide (purge reussie OU rien a purger : dans les
    deux cas il n'y a plus d'agent) ;
  - code != 0 -> `ERROR_MACHINE::`, et l'inventaire n'est PAS touche : un
    inventaire qui oublie un agent encore installe est pire qu'un inventaire qui
    n'a pas su ;
  - un `cp` de sauvegarde en echec LEVE au lieu de se faire passer pour une
    absence de fichier.
"""
import pytest

import routes.supervision as sup


class TestCommandeDeDesinstallation:
    def test_autoremove_a_disparu_des_quatre_plateformes(self):
        """Son perimetre depassait l'agent : il retirait tout paquet juge inutile."""
        for plateforme, spec in sup.AGENT_REGISTRY.items():
            assert 'autoremove' not in spec['uninstall_cmd'], plateforme

    def test_la_purge_ne_porte_que_sur_ce_qui_est_installe(self):
        """`apt-get purge` rend 100 quand le paquet n'est pas dans l'index du
        depot — pas seulement quand il n'est pas installe. Retirer le `|| true`
        sans garde ferait donc echouer la desinstallation sur toute machine ou le
        depot n'est pas configure, ce qui est le cas general."""
        cmd = sup.AGENT_REGISTRY['zabbix']['uninstall_cmd']

        assert 'dpkg-query' in cmd
        assert 'RIEN_A_PURGER' in cmd
        assert 'apt-get purge -y $P' in cmd

    def test_la_purge_n_est_plus_avalee(self):
        """C'est L'OPERATION : son code et son stderr doivent remonter."""
        cmd = sup.AGENT_REGISTRY['zabbix']['uninstall_cmd']
        ligne_purge = [l for l in cmd.split('\n') if 'apt-get purge' in l][0]

        assert '|| true' not in ligne_purge
        assert '2>/dev/null' not in ligne_purge

    def test_l_arret_du_service_reste_tolerant(self):
        """Un service deja arrete, ou un systeme sans systemd, n'est PAS un echec
        de la desinstallation."""
        cmd = sup.AGENT_REGISTRY['zabbix']['uninstall_cmd']
        arrets = [l for l in cmd.split('\n') if 'systemctl stop' in l]

        assert arrets, 'les services doivent toujours etre arretes'
        for ligne in arrets:
            assert '|| true' in ligne

    def test_les_quatre_plateformes_arretent_leur_service(self):
        for plateforme, spec in sup.AGENT_REGISTRY.items():
            assert 'systemctl stop' in spec['uninstall_cmd'], plateforme
            assert 'dpkg-query' in spec['uninstall_cmd'], plateforme


class TestConclusion:
    """`_conclut_desinstallation` : l'inventaire suit ce qu'on a pu constater."""

    def test_code_zero_vide_l_inventaire(self, monkeypatch):
        retires = []
        monkeypatch.setattr(sup, '_remove_agent',
                            lambda mid, plat: retires.append((mid, plat)))

        sortie = list(sup._conclut_desinstallation(2, 'zabbix', 'srv-dev', 0))

        assert retires == [(2, 'zabbix')]
        assert any(l.startswith('SUCCESS_MACHINE::2::') for l in sortie)

    def test_un_code_non_nul_NE_TOUCHE_PAS_l_inventaire(self, monkeypatch):
        """LE DEFAUT MESURE. Un inventaire qui oublie un agent encore installe
        est pire qu'un inventaire qui n'a pas su."""
        retires = []
        monkeypatch.setattr(sup, '_remove_agent',
                            lambda mid, plat: retires.append((mid, plat)))

        sortie = list(sup._conclut_desinstallation(2, 'zabbix', 'srv-dev', 100))

        assert retires == [], "l'inventaire ne doit pas etre vide sur un echec"
        assert any(l.startswith('ERROR_MACHINE::2::') for l in sortie)
        assert any('100' in l for l in sortie), 'le code doit etre dit'
        assert not any(l.startswith('SUCCESS_MACHINE::') for l in sortie)

    def test_un_code_inconnu_est_traite_comme_un_echec(self, monkeypatch):
        """Fail-closed : ne pas savoir n'est pas reussir."""
        retires = []
        monkeypatch.setattr(sup, '_remove_agent',
                            lambda mid, plat: retires.append((mid, plat)))

        sortie = list(sup._conclut_desinstallation(2, 'zabbix', 'srv-dev', None))

        assert retires == []
        assert any(l.startswith('ERROR_MACHINE::') for l in sortie)


class TestSauvegarde:
    """`_backup_agent_config` : « rien a sauvegarder » n'est plus « echec »."""

    def _client(self, monkeypatch, resultat):
        vues = []

        def faux_exec(client, cmd, root_pass, timeout=None, logger=None):
            vues.append(cmd)

            return resultat

        monkeypatch.setattr(sup, 'execute_as_root', faux_exec)

        return vues

    def test_le_cp_n_est_tente_que_si_le_fichier_existe(self, monkeypatch):
        """La forme `A && B || C` faisait emprunter la branche « pas de fichier »
        a un `cp` en echec. On teste l'existence D'ABORD."""
        vues = self._client(monkeypatch, ("NO_FILE", '', 0))

        sup._backup_agent_config(object(), 'mdp', '/etc/zabbix/x.conf')

        cmd = vues[0]
        assert 'if [ -f /etc/zabbix/x.conf ]' in cmd
        assert '&& cp' not in cmd, 'la forme A && B || C ne doit plus etre la'

    def test_fichier_absent_rend_None_sans_lever(self, monkeypatch):
        self._client(monkeypatch, ("NO_FILE", '', 0))

        assert sup._backup_agent_config(object(), 'mdp', '/etc/zabbix/x.conf') is None

    def test_une_copie_reussie_rend_le_chemin(self, monkeypatch):
        self._client(monkeypatch, ('', '', 0))

        chemin = sup._backup_agent_config(object(), 'mdp', '/etc/zabbix/x.conf')

        assert chemin is not None
        assert chemin.startswith('/etc/zabbix/x.conf.bak.')

    def test_une_copie_EN_ECHEC_LEVE_au_lieu_de_rendre_None(self, monkeypatch):
        """LE DEFAUT MESURE : elle rendait `None`, ce qui desarmait le repli des
        appelants (`if backup_path:`) au moment precis ou il servait."""
        self._client(monkeypatch, ('', 'cp: disque plein', 1))

        with pytest.raises(RuntimeError, match='Echec backup'):
            sup._backup_agent_config(object(), 'mdp', '/etc/zabbix/x.conf')
