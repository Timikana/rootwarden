"""
test_supervision_overrides.py - La valeur d'un override ne peut plus devenir une
ligne de configuration a elle seule.

CE QUI ETAIT MESURE AVANT LE CORRECTIF (2026-08-22, PARITE.md E-85).
`_SAFE_PARAM_RE` ne portait que sur le NOM du parametre. La valeur partait en
`f"{key}={value}\\n"`, encodee en base64 et AJOUTEE au fichier de configuration :

    POST /supervision/overrides/2  {"Timeout": "3\\nLIGNE_INJECTEE=temoin"}
    -> accepte, saut de ligne 0A retenu en base
    POST /supervision/zabbix/reconfigure
    -> fichier ecrit :   7  Timeout=3
                         8  LIGNE_INJECTEE_PAR_LA_MESURE=temoin   <- directive autonome

Sur un agent Zabbix reel, cette ligne peut etre un `UserParameter` : l'execution
d'une commande arbitraire par l'agent sur la machine supervisee. La route est
atteignable par tout role 2 portant `can_manage_supervision`, sans etre
administrateur du portail.

SPEC ATTENDUE :
  - une valeur portant un saut de ligne ou un caractere de controle est REFUSEE ;
  - le refus est NOMME dans la reponse : un refus silencieux laisse croire a un
    enregistrement (l'ancien code sautait les noms invalides sans rien dire) ;
  - une valeur legitime passe — le correctif ne doit pas fermer la porte a tout ;
  - la validation joue AUSSI A LA RELECTURE, parce que la base peut contenir des
    lignes posees avant le correctif : une validation qui ne garde que l'entree
    laisse le fichier a la merci de l'historique.

RESTE DECLARE ET NON CORRIGE : `POST /supervision/overrides/<id>` est la seule
route du module touchant une machine sans `@require_machine_access`. Inerte au
role 2 (`check_machine_access` rend vrai des ce niveau), mais absent — et hors du
perimetre autorise ici.
"""
import routes.supervision as sup


MACHINE = {'id': 2, 'name': 'srv-dev', 'ip': '10.0.0.2'}

CONFIG_GLOBALE = {
    'agent_type': 'zabbix-agent2', 'zabbix_server': '10.0.0.250',
    'hostname_pattern': '{machine.name}', 'listen_port': 10050,
    'tls_connect': 'unencrypted', 'tls_accept': 'unencrypted',
}


class TestValidationALaRelecture:
    def test_une_valeur_multiligne_ne_produit_plus_de_directive(self):
        """LE DEFAUT MESURE : la valeur sortait de sa propre ligne."""
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE,
            overrides={'Timeout': '3\nLIGNE_INJECTEE=temoin'})

        assert 'Timeout' not in lignes, "la valeur multiligne doit etre refusee"
        assert 'LIGNE_INJECTEE' not in lignes
        # Et surtout : plus AUCUNE valeur rendue ne porte de saut de ligne.
        for cle, valeur in lignes.items():
            assert '\n' not in str(valeur), f"la cle {cle} porte un saut de ligne"

    def test_un_retour_chariot_seul_est_refuse_aussi(self):
        """`\\r` suffit a couper une ligne dans un fichier de configuration."""
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE, overrides={'Timeout': '3\rAutre=1'})

        assert 'Timeout' not in lignes

    def test_un_octet_nul_est_refuse(self):
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE, overrides={'Timeout': '3\x00'})

        assert 'Timeout' not in lignes

    def test_une_valeur_legitime_passe_toujours(self):
        """Le correctif ne doit pas fermer la porte a tout."""
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE, overrides={'Timeout': '30'})

        assert lignes['Timeout'] == '30'

    def test_les_parametres_nommes_restent_prioritaires(self):
        """EXONERATION conservee : la precedence override > global tient."""
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE, overrides={'Server': '10.9.9.9'})

        assert lignes['Server'] == '10.9.9.9'
        assert lignes['ServerActive'] == '10.0.0.250', "le defaut global reste pour le reste"

    def test_une_cle_invalide_reste_refusee(self):
        """EXONERATION conservee : la CLE etait deja validee."""
        for cle in ('a b', 'x;id', '$(id)', 'a\nb'):
            lignes = sup._build_config_lines(
                CONFIG_GLOBALE, MACHINE, overrides={cle: 'valeur'})
            assert cle not in lignes, f"« {cle} » accepte"

    def test_l_interpolation_reste_appliquee(self):
        """La substitution `{machine.name}` ne doit pas avoir ete perdue."""
        lignes = sup._build_config_lines(
            CONFIG_GLOBALE, MACHINE, overrides={'Alias': 'poste-{machine.name}'})

        assert lignes['Alias'] == 'poste-srv-dev'


class TestValidationALEcriture:
    def test_une_valeur_multiligne_est_refusee_ET_NOMMEE(
            self, client, admin_headers, mock_db):
        """UN REFUS SILENCIEUX N'EST PAS UN REFUS.

        L'ancien code sautait les entrees invalides sans rien dire : l'appelant
        recevait « Overrides sauvegardes » et croyait avoir enregistre.
        """
        r = client.post('/supervision/overrides/2', headers=admin_headers,
                        json={'overrides': {'Timeout': '3\nLIGNE_INJECTEE=temoin',
                                            'ListenPort': '10051'}})

        assert r.status_code == 200
        d = r.get_json()
        assert d['saved'] == 1, "l'override legitime doit passer"
        assert len(d['rejected']) == 1
        assert d['rejected'][0]['param'] == 'Timeout'
        assert 'multiligne' in d['rejected'][0]['raison']
        # Le message chiffre les deux : rien n'est passe sous silence.
        assert '1 override(s) enregistre(s)' in d['message']
        assert '1 refuse(s)' in d['message']

    def test_un_nom_invalide_est_refuse_ET_NOMME(self, client, admin_headers, mock_db):
        r = client.post('/supervision/overrides/2', headers=admin_headers,
                        json={'overrides': {'a b': 'x'}})

        d = r.get_json()
        assert d['saved'] == 0
        assert d['rejected'][0]['raison'] == 'nom invalide'

    def test_tout_legitime_ne_signale_aucun_refus(self, client, admin_headers, mock_db):
        r = client.post('/supervision/overrides/2', headers=admin_headers,
                        json={'overrides': {'ListenPort': '10051', 'Timeout': '30'}})

        d = r.get_json()
        assert d['saved'] == 2
        assert d['rejected'] == []
        assert d['message'] == 'Overrides sauvegardes'

    def test_un_role_1_est_refuse(self, client, user_headers, mock_db):
        r = client.post('/supervision/overrides/2', headers=user_headers,
                        json={'overrides': {'ListenPort': '10051'}})

        assert r.status_code in (401, 403)
