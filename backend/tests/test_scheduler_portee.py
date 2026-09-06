"""
test_scheduler_portee.py - E-280 cote PLANIFICATEUR : « je ne sais pas quoi
scanner » ne doit jamais vouloir dire « scanne tout ».

CE QUI EST VERROUILLE ICI N'EST PAS LA GARDE D'ENTREE. Celle-la vit sur la route
et `test_ssh_audit_planification.py` la mesure. Ici on mesure la SECONDE moitie
du correctif `1d99a23`, et c'est celle qui protege la production :

    avant   else:                                   -> TOUT LE PARC
    apres   elif target_type == 'all':              -> tout le parc, CHOISI
            else: _log.error(...) + WHERE 1=0       -> AUCUNE machine

Rendre `all` explicite ne ferme rien a soi seul : **ce qui ferme, c'est que le
repli REFUSE au lieu de tout prendre.** Une planification « scanner les machines
du tag X » dont le champ est reste blanc devenait un scan RECURRENT de tout le
parc, `srv-zabbix` comprise, sur une cron, sans personne devant l'ecran.

┌─ POURQUOI CE FICHIER EXISTE ALORS QUE LE CORRECTIF EST EXERCE ──────────────┐
│ La session qui l'a pose declare l'avoir exerce sur NEUF cas. **Neuf cas      │
│ exerces une fois ne sont pas neuf cas verrouilles** : l'exercice prouve que  │
│ le code marchait a un instant, le verrou l'empeche de cesser de marcher.     │
│                                                                              │
│ Et DEUX de ces neuf portent une DECISION qui se perd au premier              │
│ « nettoyage » — voir `TestLaCasseNEstPasNormalisee`.                        │
└─────────────────────────────────────────────────────────────────────────────┘

LA MESURE : `_get_db` est remplace par une connexion factice qui ENREGISTRE ses
requetes et rend zero machine. Aucune session SSH n'est ouverte — la boucle de
scan ne recoit rien a scanner, et c'est ce qui rend ce fichier hermetique.
"""
import importlib.util
import pathlib

import pytest


def _charge_le_vrai_scheduler():
    """Charge `scheduler.py` DEPUIS SON FICHIER, sous un alias.

    ══ POURQUOI, ET C'EST LE DEFAUT QUI M'A DONNE 26 ROUGES D'UN COUP ══════

    `conftest.py:54` fait `sys.modules['scheduler'] = MagicMock()` — « pour
    eviter le demarrage du cron », et c'est une precaution juste. Mais un
    `import scheduler` dans un test rend alors le MOCK : la fonction ne
    s'execute pas, le curseur espion n'enregistre rien, et les vingt-six tests
    de ce fichier ont echoue **sans avoir mesure quoi que ce soit**.

    UN ECHEC UNIFORME SUR UN ENSEMBLE HETEROGENE EST UN DEFAUT D'INSTRUMENT
    JUSQU'A PREUVE DU CONTRAIRE — et c'etait le cas. Vingt-six rouges disaient
    « le correctif ne marche pas » ; ils disaient en realite « le module que je
    mesure n'existe pas ».

    On ne retire PAS le stub global : d'autres suites en dependent, et le
    remplacer aurait le meme effet de bord a l'envers. On charge le fichier a
    cote, sous un autre nom.

    L'import est inerte : `scheduler.py` ne demarre rien au chargement (verifie
    — seules des constantes et un `logging.getLogger` au niveau module). Aucun
    thread, aucun cron.
    """
    chemin = pathlib.Path(__file__).resolve().parents[1] / 'scheduler.py'
    spec = importlib.util.spec_from_file_location('scheduler_reel_pour_test', chemin)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scheduler = _charge_le_vrai_scheduler()


def test_TEMOIN_le_module_mesure_est_le_VRAI_et_non_un_mock():
    """LE GARDE D'INSTRUMENT, et il vaut les vingt-six autres tests.

    Sans lui, un stub — celui d'aujourd'hui ou un autre demain — rendrait ce
    fichier entierement rouge OU entierement vert selon la forme du mock, et
    dans les deux cas il ne mesurerait plus rien.
    """
    assert not hasattr(scheduler._run_scheduled_ssh_audit, 'assert_called'), (
        "le module mesure est un MagicMock : ce fichier ne mesure RIEN")
    assert callable(scheduler._run_scheduled_ssh_audit)
    import inspect
    source = inspect.getsource(scheduler._run_scheduled_ssh_audit)
    assert "elif schedule['target_type'] == 'all'" in source, (
        "la branche `all` explicite a disparu du planificateur")
    assert 'WHERE 1=0' in source, "le repli fail-closed a disparu"


PARC_ENTIER = 'FROM machines WHERE lifecycle_status IS NULL'
AUCUNE = 'WHERE 1=0'


class CurseurEspion:
    """Enregistre les requetes et rend un parc VIDE.

    Le parc vide n'est pas une commodite : c'est ce qui garantit qu'aucune
    session SSH ne part. La propriete mesuree est la REQUETE, pas son resultat.
    """

    def __init__(self):
        self.requetes = []

    def execute(self, requete, params=None):
        self.requetes.append((requete, params))

    def fetchall(self):
        return []

    def fetchone(self):
        return None

    def close(self):
        pass


class ConnexionFactice:
    def __init__(self, curseur):
        self._curseur = curseur

    def cursor(self, dictionary=False):
        return self._curseur

    def commit(self):
        pass

    def close(self):
        pass


@pytest.fixture
def espion(monkeypatch):
    curseur = CurseurEspion()
    monkeypatch.setattr(scheduler, '_get_db', lambda: ConnexionFactice(curseur))
    return curseur


def _joue(portee, valeur=None):
    return {'id': 7, 'name': 'planif-de-test',
            'target_type': portee, 'target_value': valeur}


def _selection(espion):
    """La requete de SELECTION DES MACHINES — la premiere `SELECT … FROM machines`.

    On ne lit pas « la derniere requete » : la fonction en emet d'autres apres
    (journalisation, avancement). Prendre la derniere mesurerait autre chose, et
    c'est le genre de raccourci qui rend un test vert sur le mauvais objet.
    """
    for requete, params in espion.requetes:
        if 'FROM machines' in requete:
            return requete, params
    return None, None


# ══════════════════════════════════════════════════════════════════════════════
# LE REPLI REFUSE — la branche qu'aucun controle du patch n'executait
# ══════════════════════════════════════════════════════════════════════════════

class TestLeRepliRefuseAuLieuDeToutPrendre:
    @pytest.mark.parametrize('portee', ('tag', 'environment', 'machines'))
    @pytest.mark.parametrize('valeur', (None, ''))
    def test_une_portee_restreinte_sans_valeur_ne_scanne_RIEN(
            self, espion, portee, valeur):
        """Le champ laisse blanc est le geste qui armait le piege.

        `None` et `''` sont les deux formes FAUSSES au sens de Python, donc les
        seules que `and schedule.get('target_value')` rejette. Les blancs sont
        mesures a part, ci-dessous, et ils ne se comportent PAS pareil."""
        scheduler._run_scheduled_ssh_audit(_joue(portee, valeur))

        requete, _ = _selection(espion)
        assert requete is not None, "aucune selection de machines n'a eu lieu"
        assert AUCUNE in requete, (
            f"portee '{portee}' sans valeur : la selection doit etre vide, "
            f"or elle est {requete!r}")
        assert PARC_ENTIER not in requete, (
            "LE DEFAUT MESURE : une portee restreinte sans valeur a repris "
            "tout le parc")

    @pytest.mark.parametrize('portee', ('tag', 'environment'))
    @pytest.mark.parametrize('blanc', ('   ', '\t', '\n'))
    def test_une_valeur_faite_QUE_de_blancs_ne_prend_PAS_le_parc(
            self, espion, portee, blanc):
        """⚠ MESURE QUI A CORRIGE MON ATTENDU, ET ELLE DIT UN ECART DE COUCHES.

        J'avais ecrit que les blancs tombaient dans le repli fail-closed. FAUX :
        `'   '` est une chaine NON VIDE, donc `and schedule.get('target_value')`
        la laisse passer, et la branche restreinte s'execute AVEC la valeur.

        LA ROUTE ROGNE (`.strip() or None`), LE PLANIFICATEUR NON. Les deux
        couches n'ont donc pas la meme definition de « vide ». Aucune ligne
        pareille ne peut ARRIVER par la route ; elle peut exister en base par une
        autre porte — le legacy, un SQL a la main, une version anterieure.

        Ce qui reste vrai, et c'est la propriete a verrouiller : **ce n'est
        jamais le parc entier.** Un tag de trois espaces ne trouve aucune
        machine. **Mais la surete vient alors de la VALEUR, pas d'une garde** —
        elle basculerait si cette recherche devenait un `LIKE` ou recevait un
        repli. Transmis comme tel, non corrige.
        """
        scheduler._run_scheduled_ssh_audit(_joue(portee, blanc))

        requete, params = _selection(espion)
        assert PARC_ENTIER not in requete, (
            "une valeur faite de blancs a repris tout le parc")
        assert params == (blanc,), (
            "la valeur blanche doit etre passee TELLE QUELLE en parametre : si "
            "elle est rognee ici, les deux couches se sont alignees et ce test "
            "doit etre remplace par la regle retenue")

    def test_un_type_INCONNU_ne_scanne_rien(self, espion):
        scheduler._run_scheduled_ssh_audit(_joue('tout-le-parc', 'x'))

        requete, _ = _selection(espion)
        assert AUCUNE in requete
        assert PARC_ENTIER not in requete

    def test_une_liste_de_machines_VIDE_ne_scanne_rien(self, espion):
        """`'[]'` traverse la garde d'entree — c'est une chaine non vide, et
        `test_ssh_audit_planification.py` le mesure comme une FRONTIERE. Ici on
        verifie l'autre bout : le planificateur, lui, la resout en zero machine.
        Les deux couches se lisent ensemble."""
        scheduler._run_scheduled_ssh_audit(_joue('machines', '[]'))

        requete, _ = _selection(espion)
        assert AUCUNE in requete

    def test_une_liste_ILLISIBLE_ne_scanne_rien(self, espion):
        """`json.loads` leve, `ids` retombe a `[]`. Un JSON casse ne doit pas
        valoir « tout »."""
        scheduler._run_scheduled_ssh_audit(_joue('machines', 'pas du json'))

        requete, _ = _selection(espion)
        assert AUCUNE in requete

    def test_le_refus_est_JOURNALISE_avec_ce_qui_manque(self, espion, caplog):
        """Un scan qui ne scanne rien et n'en dit rien est indiscernable d'un
        parc vide. Le journal doit nommer le type ET dire si la valeur etait la —
        c'est ce qui permet a l'exploitant de comprendre sa planification."""
        with caplog.at_level('ERROR'):
            scheduler._run_scheduled_ssh_audit(_joue('tag', ''))

        trace = caplog.text
        assert 'portee illisible' in trace
        assert "'tag'" in trace or 'tag' in trace
        assert 'vide' in trace
        assert 'AUCUNE machine' in trace


# ══════════════════════════════════════════════════════════════════════════════
# ⚠ LA DECISION QUI SE PERD AU PREMIER « NETTOYAGE »
# ══════════════════════════════════════════════════════════════════════════════

class TestLaCasseNEstPasNormalisee:
    """`'ALL'` est refuse comme type INCONNU, et c'est DELIBERE.

    Ne pas normaliser la casse est **plus strict** : normaliser accepterait
    `'TAG'`, `'Environment'`, `'MACHINES'` — donc elargirait la liste fermee par
    un geste d'hygiene. Quelqu'un ajoutera un `.lower()` par propriete un jour,
    et ce test est la pour que ce jour-la il lise cette phrase.

    ┌─ CE ROUGE-CI VOUDRAIT DIRE « L'ARBITRAGE A CHANGE » ────────────────────┐
    │ Ces assertions verrouillent une DECISION, pas une propriete evidente.   │
    │ Si elles rougissent, la casse a peut-etre ete normalisee — ce qui se     │
    │ defend, a condition d'etre CHOISI. Remplacer alors ces tests par la      │
    │ regle retenue, et ne pas les contourner.                                │
    └─────────────────────────────────────────────────────────────────────────┘
    """

    ARBITRE = ("la casse de `target_type` n'est PAS normalisee, et c'est un "
               "choix : normaliser accepterait 'TAG' et elargirait la liste "
               "fermee. Si ce rouge apparait, verifier si l'arbitrage a ete "
               "rouvert avant de conclure a une regression.")

    @pytest.mark.parametrize('variante', ('ALL', 'All', 'aLL'))
    def test_all_dans_une_autre_casse_est_un_type_inconnu(self, espion, variante):
        scheduler._run_scheduled_ssh_audit(_joue(variante))

        requete, _ = _selection(espion)
        assert AUCUNE in requete, self.ARBITRE
        assert PARC_ENTIER not in requete, self.ARBITRE

    @pytest.mark.parametrize('variante', ('TAG', 'Tag'))
    def test_tag_dans_une_autre_casse_est_un_type_inconnu(self, espion, variante):
        """Le cas qui montre pourquoi la stricte est la bonne : si l'on
        normalisait pour accepter `'ALL'`, on accepterait AUSSI ceci."""
        scheduler._run_scheduled_ssh_audit(_joue(variante, 'production'))

        requete, _ = _selection(espion)
        assert AUCUNE in requete, self.ARBITRE


# ══════════════════════════════════════════════════════════════════════════════
# LES CONTRE-CAS — sans eux, un planificateur qui refuse TOUT passerait
# ══════════════════════════════════════════════════════════════════════════════

class TestLesPorteesQuiDoiventEncoreABOUTIR:
    def test_all_EXPLICITE_prend_bien_tout_le_parc(self, espion):
        """LE CONTRE-CAS PRINCIPAL. Un correctif qui refuserait tout satisfait
        chacun des tests precedents — celui-ci est le seul qui l'interdise.

        Et il verrouille au passage l'exclusion des ARCHIVEES, qui est la
        definition du parc pour un GESTE (les archivees sont selectionnables
        ailleurs, mais on n'ouvre pas de session SSH sur une machine
        decommissionnee — E-242)."""
        scheduler._run_scheduled_ssh_audit(_joue('all'))

        requete, _ = _selection(espion)
        assert PARC_ENTIER in requete
        assert AUCUNE not in requete
        assert "!= 'archived'" in requete

    def test_un_tag_RENSEIGNE_selectionne_par_le_tag(self, espion):
        scheduler._run_scheduled_ssh_audit(_joue('tag', 'production'))

        requete, params = _selection(espion)
        assert 'machine_tags' in requete
        assert AUCUNE not in requete
        assert params == ('production',), 'le tag doit etre passe en PARAMETRE'
        assert "!= 'archived'" in requete

    def test_un_environnement_RENSEIGNE_selectionne_par_l_environnement(self, espion):
        scheduler._run_scheduled_ssh_audit(_joue('environment', 'PROD'))

        requete, params = _selection(espion)
        assert 'environment = %s' in requete
        assert params == ('PROD',)
        assert "!= 'archived'" in requete

    def test_une_liste_de_machines_VALIDE_selectionne_ces_machines(self, espion):
        scheduler._run_scheduled_ssh_audit(_joue('machines', '[2, 3]'))

        requete, params = _selection(espion)
        assert AUCUNE not in requete
        assert 'id IN' in requete
        assert list(params) == [2, 3]

    def test_les_identifiants_ne_sont_JAMAIS_interpoles(self, espion):
        """Les quatre branches passent par des paramETRES. Une valeur de tag
        vient de la base, qui la tient d'un formulaire : l'interpoler ferait de
        la table `ssh_audit_schedules` un vecteur d'injection differee."""
        scheduler._run_scheduled_ssh_audit(_joue('tag', "'; DROP TABLE machines --"))

        requete, params = _selection(espion)
        assert 'DROP TABLE' not in requete, "la valeur a ete interpolee dans le SQL"
        assert params == ("'; DROP TABLE machines --",)
