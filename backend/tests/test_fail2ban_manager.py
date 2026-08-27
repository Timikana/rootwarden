"""
test_fail2ban_manager.py - E-174 : une adresse IP ne doit pas pouvoir porter une
commande root.

QA-003. Ecrit par la session QA, sans avoir lu la sonde de la session 4 : un test
qui tombe d'accord avec elle vaudra quelque chose, et une divergence serait un vrai
signal. Les faits sur le code viennent de sa lecture directe, ici et dans le
conteneur.

┌─ CE QU'ETAIT LE DEFAUT ──────────────────────────────────────────────────────┐
│ `_validate_ip` appelait `ipaddress.ip_address(ip)` pour son seul effet de     │
│ bord, jetait l'objet, et rendait la chaine RECUE. Or l'identifiant de portee  │
│ IPv6 — ce qui suit un `%` — n'est soumis a aucune contrainte. La valeur       │
│ repartait dans un f-string vers `fail2ban-client`, puis dans un `sh -c`       │
│ distant : execution de commande en root.                                      │
│                                                                               │
│ DEUX vecteurs, pas un. Le second est pire : dans `manage_whitelist`, la ligne │
│ composee part dans un `sed -i '/\\[DEFAULT\\]/a\\<ligne>'`, ou une apostrophe  │
│ FERME l'argument de `sed`.                                                    │
└───────────────────────────────────────────────────────────────────────────────┘

┌─ COMPTER LES VERROUS : UN SEUL LEVE NE ROUVRE RIEN ──────────────────────────┐
│ Le correctif en pose QUATRE, et ce fichier les mesure UN PAR UN — parce qu'un │
│ verrou dont on ne mesure que l'effet combine est un verrou qu'on peut retirer │
│ sans que rien ne rougisse :                                                   │
│                                                                               │
│   1. `_validate_ip` refuse le `%`            (la boucle)                      │
│   2. `_validate_ip` rend une forme NORMALISEE (elle ne rend plus le recu)     │
│   3. `shlex.quote` a l'interieur de la commande (la ceinture)                 │
│   4. `_entree_whitelist_sure` filtre aussi la RELECTURE du fichier distant    │
│   5. la garde fail-closed sur la ligne composee (le dernier rempart)          │
└───────────────────────────────────────────────────────────────────────────────┘

Ce fichier ne joint aucune machine : `execute_as_root` est remplacee par un
enregistreur qui retient CHAQUE commande composee. C'est sur ces chaines que
portent les assertions — pas sur un effet distant, qui demanderait le banc.
"""

import ipaddress
from unittest.mock import patch

import pytest

import fail2ban_manager as f2b


# ── Les charges mesurees le 2026-08-27 ───────────────────────────────────────
#
# Chacune est une adresse IPv6 de lien-local SYNTAXIQUEMENT VALIDE suivie d'un
# identifiant de portee. C'est ce qui les rend dangereuses : `ip_address()` les
# accepte, et l'ancienne version rendait la chaine telle quelle.
#
# La liste couvre les familles de metacaracteres du shell separement — un filtre
# qui n'en fermerait qu'une passerait pour bon sur un echantillon plus etroit.

CHARGES_PORTEE = [
    'fe80::1%;id;',              # separateur de commande
    'fe80::1%$(id)',             # substitution moderne
    'fe80::1%`id`',              # substitution ancienne
    "fe80::1%'",                 # ferme l'apostrophe de `sed` — le second vecteur
    'fe80::1%"',                 # ferme un guillemet
    'fe80::1%|id',               # tube
    'fe80::1%&id',               # arriere-plan
    'fe80::1%\nid',              # saut de ligne
    'fe80::1%eth0',              # portee LEGITIME, refusee elle aussi : la regle
                                 # ne fait pas de tri, et c'est voulu
]


# ═════════════════════════════════════════════════════════════════════════════
# Verrou 1 — le `%` est refuse
# ═════════════════════════════════════════════════════════════════════════════

class TestRefusDeLIdentifiantDePortee:

    @pytest.mark.parametrize('charge', CHARGES_PORTEE)
    def test_toute_portee_est_refusee(self, charge):
        with pytest.raises(ValueError):
            f2b._validate_ip(charge)

    @pytest.mark.parametrize('charge', CHARGES_PORTEE)
    def test_la_bibliotheque_standard_les_accepterait(self, charge):
        """CE QUI REND CES CHARGES DANGEREUSES, mesure plutot qu'affirme.

        Sans cette assertion, on ne saurait pas si le refus vient du correctif ou
        du simple fait que la charge n'est pas une adresse. Elle etablit que
        `ipaddress` les accepte — donc que le refus est bien l'oeuvre du garde,
        et que le retirer rouvrirait quelque chose.

        Deux charges portent un metacaractere que `ipaddress` rejette de
        lui-meme ; elles sont ecartees ici, et c'est dit plutot que masque.
        """
        try:
            ipaddress.ip_address(charge)
        except ValueError:
            pytest.skip(f"{charge!r} est refusee par ipaddress elle-meme : "
                        "elle ne demontre rien du garde")

    def test_le_message_de_refus_nomme_la_cause(self):
        with pytest.raises(ValueError, match='portee'):
            f2b._validate_ip('fe80::1%eth0')


# ═════════════════════════════════════════════════════════════════════════════
# Verrou 2 — la valeur RENDUE est normalisee, pas la valeur recue
# ═════════════════════════════════════════════════════════════════════════════

class TestNormalisation:
    """LA PROPRIETE QUI DISTINGUE L'ANCIENNE VERSION DE LA NOUVELLE.

    L'ancienne appelait `ip_address()` pour son effet de bord et rendait la
    chaine RECUE. Une assertion « la fonction ne leve pas » passerait donc a
    l'identique sur les deux. Ce qui les separe est la valeur rendue.
    """

    @pytest.mark.parametrize('recu,attendu', [
        ('FE80::0001', 'fe80::1'),
        ('2001:0DB8:0000:0000:0000:0000:0000:0001', '2001:db8::1'),
        (' 8.8.8.8 ', '8.8.8.8'),
        ('203.0.113.7', '203.0.113.7'),
        ('::1', '::1'),
    ])
    def test_la_valeur_rendue_est_la_forme_normalisee(self, recu, attendu):
        assert f2b._validate_ip(recu) == attendu

    def test_la_normalisation_rend_le_retrait_possible(self):
        """Effet de bord du correctif, dans le bon sens.

        Retirer `FE80::0001` d'une liste qui contient `fe80::1` echouait avec une
        comparaison textuelle. Ce n'est pas une propriete de securite, c'est une
        capacite — et une capacite non mesuree se reperd.
        """
        assert f2b._validate_ip('FE80::0001') == f2b._validate_ip('fe80::1')


class TestLeCasNormalNEstPasCasse:
    """UN CORRECTIF EVIDENT PEUT CASSER LE CAS NORMAL.

    Les trois classes ci-dessus seraient toutes vertes sur une fonction qui
    refuse TOUT. Celle-ci est la moitie qui manque.
    """

    @pytest.mark.parametrize('adresse', [
        '8.8.8.8', '203.0.113.7', '192.0.2.1', '10.0.0.1',
        '2001:db8::1', '::1', 'fe80::1',
    ])
    def test_une_adresse_legitime_passe(self, adresse):
        assert f2b._validate_ip(adresse) == str(ipaddress.ip_address(adresse))

    @pytest.mark.parametrize('valeur', ['', '   ', 'abc', '999.999.999.999',
                                        '8.8.8', 'localhost'])
    def test_ce_qui_n_est_pas_une_adresse_est_refuse(self, valeur):
        with pytest.raises(ValueError):
            f2b._validate_ip(valeur)

    def test_le_format_CIDR_est_refuse_par_cette_fonction(self):
        """CARACTERISATION DE L'ETAT ACTUEL, pas expression d'un souhait.

        `_validate_ip` refuse `10.0.0.0/8` — c'etait deja vrai avant le
        correctif, ce n'est donc pas une regression. La consequence, elle, merite
        d'etre ecrite : on ne peut pas ajouter un RESEAU a la liste blanche par
        cette route, alors que `_entree_whitelist_sure` en accepte (les deux
        entrees par defaut du module sont `127.0.0.1/8` et `::1`).

        Les deux fonctions n'ont donc pas le meme domaine, et c'est delibere :
        l'une valide ce que le CLIENT envoie, l'autre ce que le FICHIER contient.
        """
        with pytest.raises(ValueError):
            f2b._validate_ip('10.0.0.0/8')


# ═════════════════════════════════════════════════════════════════════════════
# Verrou 3 — la ceinture : `shlex.quote` A L'INTERIEUR de la commande
# ═════════════════════════════════════════════════════════════════════════════

class TestLaCeintureTientSansLaBoucle:
    """MESURER CHAQUE VERROU SEPAREMENT.

    `_validate_ip` ferme le vecteur connu ; `shlex.quote` ferme la CLASSE. Tant
    qu'on ne mesure que leur effet combine, retirer la citation ne ferait rougir
    aucun test — et le jour ou un autre caractere passerait le validateur, plus
    rien ne protegerait.

    On simule donc un validateur PERCE — celui d'avant le correctif, qui rendait
    la chaine recue — et on verifie que la commande composee porte quand meme la
    charge CITEE, c'est-a-dire inerte pour le `sh -c` distant.
    """

    CHARGE = "fe80::1%';id;'"

    def test_la_charge_repart_citee_et_non_interpretable(self):
        commandes = []

        def enregistre(client, commande, mot_de_passe, timeout=None):
            commandes.append(commande)
            return ('', '', 0)

        # Validateur d'AVANT le correctif : il rend ce qu'il recoit.
        with patch.object(f2b, '_validate_ip', side_effect=lambda v: v), \
             patch.object(f2b, 'execute_as_root', side_effect=enregistre):
            f2b.ban_ip(object(), 'mot-de-passe', 'sshd', self.CHARGE)

        assert len(commandes) == 1
        commande = commandes[0]

        # La charge est PRESENTE — on ne l'a pas filtree, c'est le postulat du
        # test — mais elle est enfermee : aucun `;` ni `$(` n'est actif.
        assert "'" in commande, 'la valeur doit etre citee'
        assert not commande.endswith(';id;'), \
            'la charge ne doit pas terminer la commande a decouvert'

        # La mesure qui vaut : ce que le shell distant en ferait. `shlex.split`
        # analyse comme un shell POSIX ; la charge doit rester UN SEUL argument.
        import shlex
        morceaux = shlex.split(commande)
        assert morceaux[:4] == ['fail2ban-client', 'set', 'sshd', 'banip']
        assert morceaux[4] == self.CHARGE, \
            f'la charge doit rester un argument unique, elle a ete decoupee : {morceaux}'
        assert len(morceaux) == 5, \
            f'aucun morceau supplementaire ne doit apparaitre : {morceaux}'

    def test_le_nom_de_jail_est_cite_lui_aussi(self):
        """La meme classe de defaut, sur l'autre valeur composee. `_validate_jail`
        la ferme deja ; la citation est le second verrou, et il se mesure a part."""
        commandes = []

        with patch.object(f2b, '_validate_jail', side_effect=lambda v: v), \
             patch.object(f2b, 'execute_as_root',
                          side_effect=lambda c, cmd, p, timeout=None: (commandes.append(cmd), ('', '', 0))[1]):
            f2b.ban_ip(object(), 'mot-de-passe', 'sshd;id', '8.8.8.8')

        import shlex
        assert shlex.split(commandes[0])[2] == 'sshd;id'


# ═════════════════════════════════════════════════════════════════════════════
# Verrou 4 — la RELECTURE du fichier distant est filtree, pas seulement l'ecriture
# ═════════════════════════════════════════════════════════════════════════════

class TestPredicatDeListeBlanche:
    """`_entree_whitelist_sure` est un predicat PUR : elle rend un booleen et ne
    leve pas. Son domaine n'est pas celui de `_validate_ip` — elle accepte le
    CIDR, parce que les deux entrees par defaut du module en sont."""

    @pytest.mark.parametrize('valeur', [
        '127.0.0.1/8', '::1', '10.0.0.0/8', '8.8.8.8', '2001:db8::/32', 'fe80::1',
    ])
    def test_une_entree_legitime_est_acceptee(self, valeur):
        assert f2b._entree_whitelist_sure(valeur) is True

    @pytest.mark.parametrize('valeur', CHARGES_PORTEE)
    def test_toute_portee_est_ecartee(self, valeur):
        assert f2b._entree_whitelist_sure(valeur) is False

    @pytest.mark.parametrize('valeur', [
        '', '   ', None, 'ignoreip', '; id', '$(id)', '`id`', "8.8.8.8'",
        '8.8.8.8 && id', '/etc/passwd',
    ])
    def test_ce_qui_n_est_ni_adresse_ni_reseau_est_ecarte(self, valeur):
        assert f2b._entree_whitelist_sure(valeur) is False

    def test_elle_ne_leve_jamais(self):
        """Un predicat qui leve la ou l'appelant attend un booleen transforme un
        filtre en panne. Les deux compréhensions de `manage_whitelist` l'appellent
        sur CHAQUE entree du fichier distant, dont le contenu n'est pas maitrise."""
        for valeur in ['', None, '\x00', 'a' * 5000, '::1%' * 100]:
            assert f2b._entree_whitelist_sure(valeur) in (True, False)


class ExecutionRootFactice:
    """Remplace `execute_as_root`. Retient CHAQUE commande composee.

    Aucune machine n'est jointe : ce sont les chaines qui sont mesurees. La
    premiere commande de `manage_whitelist` lit `ignoreip` dans le fichier
    distant — c'est par sa reponse qu'on injecte l'etat du fichier, donc le
    chemin de la RELECTURE.
    """

    def __init__(self, ligne_ignoreip=''):
        self.commandes = []
        self.ligne_ignoreip = ligne_ignoreip

    def __call__(self, client, commande, mot_de_passe, timeout=None):
        self.commandes.append(commande)
        if 'ignoreip' in commande and commande.startswith('grep'):
            return (self.ligne_ignoreip, '', 0)
        return ('', '', 0)

    @property
    def tout(self):
        return '\n'.join(self.commandes)

    @property
    def ecritures(self):
        """Les commandes qui MODIFIENT le fichier — celles ou une charge compte."""
        return [c for c in self.commandes if 'sed -i' in c or 'base64 -d' in c]


class TestRelectureDuFichierDistant:
    """LA LECON DE V10a : VALIDER AUX DEUX BOUTS.

    La liste blanche n'a pas qu'une source. Ce que le client envoie passe par
    `_validate_ip` — mais le reste est RELU dans `/etc/fail2ban/jail.local`. Une
    charge posee a la main, ou ecrite avant le correctif, reviendrait par la
    relecture et repartirait dans le `sed`.

    Un test qui n'exercerait que l'entree du client serait vert sur un correctif
    qui ne pose qu'un seul des deux verrous.
    """

    CHARGE = "fe80::1%';echo VOLE;'"

    def _appelle(self, action, ip, ligne):
        execution = ExecutionRootFactice(ligne_ignoreip=ligne)
        with patch.object(f2b, 'execute_as_root', side_effect=execution), \
             patch.object(f2b, 'restart_fail2ban', return_value=('', '', 0)):
            resultat = f2b.manage_whitelist(object(), 'mot-de-passe', action, ip)
        return resultat, execution

    def test_une_charge_DEJA_dans_le_fichier_ne_repart_pas(self):
        resultat, execution = self._appelle(
            'add', '8.8.8.8',
            f'ignoreip = 127.0.0.1/8 ::1 {self.CHARGE}')

        assert self.CHARGE not in execution.tout, \
            'la charge relue dans le fichier distant est repartie dans une commande'
        assert self.CHARGE not in resultat['ips']
        assert '8.8.8.8' in resultat['ips'], "l'ajout demande doit avoir eu lieu"

    def test_les_entrees_saines_survivent_au_filtre(self):
        """Le filtre doit ecarter la charge ET RIEN D'AUTRE. Un filtre trop large
        viderait la liste blanche d'une machine — ce qui, sur fail2ban, se paie en
        exclusion de l'exploitant lui-meme."""
        resultat, _ = self._appelle(
            'add', '8.8.8.8',
            f'ignoreip = 127.0.0.1/8 ::1 {self.CHARGE} 10.0.0.0/8')

        assert resultat['ips'] == ['127.0.0.1/8', '::1', '10.0.0.0/8', '8.8.8.8']

    def test_un_retrait_filtre_aussi(self):
        """`remove` recompose la ligne autant qu'`add` : le verrou doit y etre
        aussi. Chercher la branche jumelle est une regle de ce chantier."""
        _resultat, execution = self._appelle(
            'remove', '8.8.8.8',
            f'ignoreip = 8.8.8.8 {self.CHARGE}')

        assert self.CHARGE not in execution.tout

    def test_la_lecture_seule_n_ecrit_rien(self):
        _resultat, execution = self._appelle('list', '', 'ignoreip = 127.0.0.1/8 ::1')

        assert execution.ecritures == [], \
            f'une lecture a compose une commande d\'ecriture : {execution.ecritures}'

    def test_le_drapeau_lue_distingue_le_fichier_du_defaut(self):
        """E-168. Une liste SUPPOSEE et une liste LUE ne doivent pas se presenter
        pareil : sans ce drapeau, l'interface affiche une liste blanche qui
        n'existe sur aucune machine, sans pouvoir le savoir ni le dire."""
        lue, _ = self._appelle('list', '', 'ignoreip = 8.8.8.8')
        supposee, _ = self._appelle('list', '', '')

        assert lue['lue'] is True
        assert supposee['lue'] is False
        assert supposee['ips'] == ['127.0.0.1/8', '::1'], \
            'le defaut suppose reste celui du module'

    def test_une_charge_envoyee_par_le_client_n_atteint_aucune_commande(self):
        """Le premier verrou, mesure au niveau de la fonction entiere : le refus
        doit arriver AVANT toute ecriture. Une exception levee apres le `sed`
        laisserait la charge partie."""
        execution = ExecutionRootFactice(ligne_ignoreip='ignoreip = 127.0.0.1/8')

        with patch.object(f2b, 'execute_as_root', side_effect=execution), \
             patch.object(f2b, 'restart_fail2ban', return_value=('', '', 0)):
            with pytest.raises(ValueError):
                f2b.manage_whitelist(object(), 'mot-de-passe', 'add', self.CHARGE)

        assert execution.ecritures == [], \
            'une charge refusee a quand meme fait composer une ecriture'


# ═════════════════════════════════════════════════════════════════════════════
# Verrou 5 — la garde fail-closed sur la ligne composee
# ═════════════════════════════════════════════════════════════════════════════

class TestGardeFailClosed:
    """« Si un jour un troisieme chemin alimente `current_ips`, c'est ici que ca
    s'arrete » — c'est ce que le commentaire du correctif affirme. Une affirmation
    de commentaire n'est pas une propriete : ce chantier compte cinq en-tetes qui
    annoncent un acces plus strict que leur code.

    On la met donc a l'epreuve en NEUTRALISANT les deux filtres qui la precedent,
    ce qui simule exactement ce troisieme chemin.
    """

    def test_la_composition_est_refusee_si_les_filtres_amont_tombent(self):
        execution = ExecutionRootFactice(
            ligne_ignoreip="ignoreip = 127.0.0.1/8 fe80::1%';id;'")

        with patch.object(f2b, '_entree_whitelist_sure', return_value=True), \
             patch.object(f2b, 'execute_as_root', side_effect=execution), \
             patch.object(f2b, 'restart_fail2ban', return_value=('', '', 0)):
            with pytest.raises(ValueError, match='refusee'):
                f2b.manage_whitelist(object(), 'mot-de-passe', 'add', '8.8.8.8')

        assert execution.ecritures == [], \
            'la garde a leve APRES avoir compose une ecriture : elle arrive trop tard'

    def test_elle_laisse_passer_une_ligne_ordinaire(self):
        """L'autre moitie : une garde qui refuse tout n'est pas une garde."""
        execution = ExecutionRootFactice(ligne_ignoreip='ignoreip = 127.0.0.1/8 ::1')

        with patch.object(f2b, 'execute_as_root', side_effect=execution), \
             patch.object(f2b, 'restart_fail2ban', return_value=('', '', 0)):
            resultat = f2b.manage_whitelist(object(), 'mot-de-passe', 'add', '8.8.8.8')

        assert resultat['success'] is True
        assert execution.ecritures, 'un ajout legitime doit composer une ecriture'


# ═════════════════════════════════════════════════════════════════════════════
# CE QUI RESTE OUVERT — mesure, non corrige, transmis au Lead
# ═════════════════════════════════════════════════════════════════════════════

class TestLaLectureEtLEcritureNeDisentPasLaMemeChose:
    """DEUX LECTURES DE LA MEME DONNEE QUI DIVERGENT.

    `action == 'list'` sort AVANT le filtre : la lecture rend donc la liste
    BRUTE du fichier, entree illisible comprise. Un `add` ou un `remove`
    ulterieur la fait disparaitre — journalisee cote serveur, silencieuse pour
    l'appelant.

    Vu de l'exploitant : une entree est affichee, un geste sans rapport est fait,
    l'entree n'est plus la. Et le drapeau `lue` continue de dire `true` — il ne
    ment pas sur l'ORIGINE de la liste, mais il ne dit rien du fait que la liste
    REECRITE n'est pas celle qui a ete lue.

    Meme famille qu'E-168 (« la liste blanche affichee est SUPPOSEE et non lue »)
    et que le defaut de D1, ou « Verifier l'integrite » et « Sceller les
    orphelines » rendaient deux verdicts opposes sur la meme seconde. La regle du
    chantier est de les faire repondre COTE A COTE : separement, chacun passe.

    ── POURQUOI CE TEST EST EN `xfail(strict)` ET PAS EN ASSERTION ────────────
    La propriete enoncee ci-dessous — « ce que la lecture montre, l'ecriture le
    preserve, ou bien elle dit ce qu'elle a retire » — ne prejuge PAS de la forme
    du correctif : filtrer aussi a la lecture, ou nommer les entrees ecartees
    dans la reponse, la satisferaient toutes deux. Laquelle retenir touche le
    CONTRAT de la route, donc le portage : c'est une decision du Lead et de la
    session qui tient `laravel/`, pas la mienne.

    Le marqueur strict garantit qu'au jour du correctif la suite rougira, et
    qu'il faudra revenir ecrire la propriete pour de bon — le meme mecanisme qui
    a fait remonter la moitie restante d'E-164.
    """

    CHARGE = "fe80::1%';echo VOLE;'"

    @pytest.mark.xfail(strict=True,
                       reason="action == 'list' sort avant le filtre : la lecture "
                              "montre une entree que l'ecriture supprime en silence")
    def test_ce_que_la_lecture_montre_l_ecriture_le_preserve_ou_le_nomme(self):
        ligne = f'ignoreip = 127.0.0.1/8 {self.CHARGE}'

        def appelle(action, ip):
            execution = ExecutionRootFactice(ligne_ignoreip=ligne)
            with patch.object(f2b, 'execute_as_root', side_effect=execution), \
                 patch.object(f2b, 'restart_fail2ban', return_value=('', '', 0)):
                return f2b.manage_whitelist(object(), 'mot-de-passe', action, ip)

        vue = appelle('list', '')
        apres = appelle('add', '8.8.8.8')

        perdues = [x for x in vue['ips'] if x not in apres['ips']]

        assert not perdues or 'ecartees' in apres, (
            f"la lecture annonce {vue['ips']}, l'ecriture rend {apres['ips']} : "
            f"{perdues} ont disparu sans que la reponse le dise"
        )
