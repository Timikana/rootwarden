"""
test_verdicts_deux_cents.py - QUELLES ROUTES PEUVENT RENDRE 200 AVEC `success: false` ?

QA-011, premiere moitie de la JOINTURE appelant -> route.

┌─ POURQUOI CETTE LISTE EXISTE ────────────────────────────────────────────────┐
│ Le releve des appelants (`docs/migration/QA-APPELANTS.md`) a etabli qu'AUCUN  │
│ appelant du portage ne presente aujourd'hui un refus comme une reussite —     │
│ **mais pas parce qu'ils lisent tous `success`** : parce que tout refus porte  │
│ encore un statut HTTP non-200. Tester `.ok` et tester `success` rendent donc  │
│ le meme verdict.                                                              │
│                                                                              │
│ **Ils sont couples a une COINCIDENCE.** Et une coincidence se rompt : trois   │
│ routes l'ont rompue le 2026-08-27 (E-184, E-186, E-187), et c'est ce qui a    │
│ produit le defaut du bouton « Detecter la version » — `reponse.ok` vrai,      │
│ `version` nulle, et l'ecran affirmant « Aucun agent installe. Le releve       │
│ precedent a ete efface. » Deux affirmations fausses, dont une qui annoncait   │
│ une ecriture que le correctif venait de supprimer.                            │
└──────────────────────────────────────────────────────────────────────────────┘

CE QUE CE FICHIER MESURE, ET CE QU'IL NE MESURE PAS
---------------------------------------------------
Il mesure **le cote backend de la jointure** : quelles routes appartiennent a la
famille « 200 + `success: false` ». Il ne dit PAS quel appelant les consomme —
cette moitie-la demande de resoudre, depuis le JavaScript, une URL construite en
PHP, et elle n'est pas faite. Elle est nommee dans `QA-APPELANTS.md` §6.

La regle qui rend cette liste utile :

    Quand une route REJOINT cette famille, ses appelants doivent etre relus.
    Rien ne change chez eux : ils sont invisibles au diff du correctif.

C'est la formulation generale de ce qui a coute deux heures le 2026-08-27 :
*quand une valeur cesse d'etre constante, l'endroit a auditer n'est pas celui qui
la teste, c'est celui qui ne la testait PAS.*

L'ANALYSE EST FAITE PAR ARBRE SYNTAXIQUE, SANS RIEN IMPORTER
------------------------------------------------------------
`import server` lance un ordonnanceur au niveau module. On lit donc l'arbre —
c'est la seule facon de mesurer une structure sans executer ce qu'elle declare.
Emprunte a `test_invariant_machine_id.py`, meme raison.
"""
import ast
import pathlib

import pytest

RACINE = pathlib.Path(__file__).resolve().parent.parent / 'routes'

# En dessous, l'analyse n'a rien vu : c'est l'INSTRUMENT qui est casse, pas le
# code. Une enumeration vide satisfait toutes les proprietes universelles.
PLANCHER_ROUTES = 150


def _nom(noeud):
    cible = noeud.func if isinstance(noeud, ast.Call) else noeud
    if isinstance(cible, ast.Name):
        return cible.id
    if isinstance(cible, ast.Attribute):
        return cible.attr
    return ''


def _cles(noeud):
    """Les cles litterales d'un dict litteral, avec leur valeur."""
    if not isinstance(noeud, ast.Dict):
        return {}
    return {k.value: v for k, v in zip(noeud.keys, noeud.values)
            if isinstance(k, ast.Constant)}


def _famille(fn):
    """A quelle famille de verdict cette route appartient-elle ?

    `dur`         un `return jsonify({'success': False})` SANS statut, donc 200 ;
    `conditionnel` un `success` calcule — il PEUT valoir False a 200 ;
    `jamais`      tout refus porte un statut non-200.

    Le cas `conditionnel` est le plus important des trois et le moins visible :
    `'success': rc == 0` rend 200 quoi qu'il arrive. Une lecture rapide n'y voit
    pas de refus ; l'appelant qui teste `.ok` n'en voit pas davantage.
    """
    conditionnel = False
    for r in ast.walk(fn):
        if not isinstance(r, ast.Return) or r.value is None:
            continue
        valeur, statut = r.value, 200
        if isinstance(valeur, ast.Tuple) and len(valeur.elts) >= 2:
            s = valeur.elts[1]
            statut = s.value if isinstance(s, ast.Constant) else '?'
            valeur = valeur.elts[0]
        if statut != 200:
            continue
        if not (isinstance(valeur, ast.Call) and _nom(valeur) == 'jsonify'):
            continue
        succes = _cles(valeur.args[0]).get('success') if valeur.args else None
        if succes is None:
            continue
        if isinstance(succes, ast.Constant):
            if succes.value is False:
                return 'dur'
        else:
            conditionnel = True
    return 'conditionnel' if conditionnel else 'jamais'


def _rend_un_flux(fn):
    """La route rend-elle un FLUX plutot qu'un corps JSON ?

    ══ LA TROISIEME FAMILLE, ET ELLE EST PIRE QUE LES DEUX AUTRES ═══════════

    Trouvee le 2026-08-28 par la session BACKEND LARAVEL, sur `/docker/scan_all` :

        return Response(stream(), mimetype='text/plain')

    **Le 200 part AVANT que le travail ne commence.** Il n'y a donc pas de champ
    `success` du tout — le verdict vit dans les LIGNES du corps.

    Pour les deux autres familles, `reponse.ok` donne le bon verdict par
    COINCIDENCE, et la coincidence peut se rompre. Ici il n'y a pas de
    coincidence a rompre : `.ok` est **structurellement denue de sens**, il l'a
    toujours ete et il le restera.

    Et le defaut se double d'un second, structurel lui aussi : un appelant qui
    fait `await r.json()` sur du JSON-lines leve a CHAQUE fois. L'exception
    avalee, son `corps` vaut `null` par construction — le compte rendu par
    machine n'etait pas mal lu, **il n'etait pas lu du tout**.

    C'est pourquoi cette famille est un ATTRIBUT et non un membre de la partition
    a trois : une route peut rendre un 400 en JSON puis un flux en 200, et les
    deux proprietes doivent se dire ensemble.
    """
    for r in ast.walk(fn):
        if not isinstance(r, ast.Return) or r.value is None:
            continue
        v = r.value
        if isinstance(v, ast.Tuple) and v.elts:
            v = v.elts[0]
        if isinstance(v, ast.Call) and _nom(v) in ('Response', 'stream_with_context'):
            return True
    return False


def _routes():
    trouvees = []
    for fichier in sorted(RACINE.glob('*.py')):
        arbre = ast.parse(fichier.read_text(encoding='utf-8'), filename=str(fichier))
        for fn in ast.walk(arbre):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(_nom(d) == 'route' for d in fn.decorator_list):
                continue
            trouvees.append({'fichier': fichier.name, 'nom': fn.name,
                             'famille': _famille(fn), 'flux': _rend_un_flux(fn)})
    return trouvees


@pytest.fixture(scope='module')
def routes():
    return _routes()


# ── L'ETAT CONNU, mesure le 2026-08-28 ──────────────────────────────────────
#
# Les routes qui rendent 200 avec `success: False` ECRIT EN DUR. Un appelant qui
# ne teste que le statut y presente un refus comme une reussite — pas « un
# jour » : aujourd'hui.
VERDICT_A_200_CONNU = {
    ('cve.py', 'cve_compare'),
    ('fail2ban.py', 'fail2ban_ban'),
    ('fail2ban.py', 'fail2ban_unban'),
    ('fail2ban.py', 'fail2ban_unban_all'),
    ('iptables.py', 'validate_iptables'),
    ('monitoring.py', 'check_linux_version'),
    ('ssh.py', 'test_platform_key'),
    # ── `ssh.py:remove_user_keys` EST SORTIE DE LA FAMILLE — E-215 ───────────
    #
    # Retiree le 2026-08-28, le jour meme ou cette liste a ete figee, et par la
    # garde symetrique : elle a rougi au PREMIER rejeu et m'a fait REGARDER.
    #
    # La cause est la bonne des deux : la route a ete CORRIGEE. Ses deux refus
    # portent desormais un statut — 400 pour la cle de plateforme protegee, 404
    # pour l'absence d'inventaire. Elle ne rend plus 200 avec `success: false`.
    #
    # Sans cette garde, l'entree serait restee : une liste qui se raccourcit en
    # silence passe au vert en ne mesurant plus rien.
    ('ssh.py', 'delete_remote_user'),
    ('supervision.py', 'zabbix_version'),
    ('supervision.py', 'generic_version'),
    ('wazuh.py', 'detect'),
}


# ── LES ROUTES QUI RENDENT UN FLUX, mesurees le 2026-08-28 ──────────────────
#
# Leur `200` part avant le travail : `reponse.ok` n'y est pas un verdict, et il
# n'y a aucun champ `success` a lire. Un appelant doit lire le CORPS, ligne par
# ligne — et un appelant qui fait `r.json()` dessus echoue par construction.
FLUX_CONNUS = {
    ('cve.py', 'cve_scan'),
    ('cve.py', 'cve_scan_all'),
    ('docker.py', 'docker_scan_all'),
    ('iptables.py', 'iptables_logs'),
    ('ssh.py', 'stream_logs'),
    ('supervision.py', 'zabbix_deploy'),
    ('supervision.py', 'zabbix_uninstall'),
    ('supervision.py', 'zabbix_reconfigure'),
    ('supervision.py', 'generic_deploy'),
    ('supervision.py', 'generic_uninstall'),
    ('supervision.py', 'generic_reconfigure'),
    ('updates.py', 'update_server'),
    ('updates.py', 'apply_security_updates'),
    ('updates.py', 'stream_update_logs'),
    ('updates.py', 'dry_run_update'),
}


# ── LA FAMILLE CONDITIONNELLE, FIGEE A SON TOUR — mesure du 2026-08-28 ─────
#
# ══ ET MON REFUS DE LA FIGER ETAIT UNE ERREUR DE RAISONNEMENT ══════════════
#
# J'avais ecrit : « on ne les fige pas une par une — elles bougent a chaque
# correctif de la famille "une reussite se verifie" ». C'etait traiter le
# MOUVEMENT comme une raison de ne pas mesurer, alors que le mouvement EST
# l'evenement dont je veux etre prevenue : une route qui rejoint cette famille
# est une route dont les appelants doivent etre relus, exactement comme pour
# `dur`.
#
# La preuve est arrivee en vingt-quatre heures : la famille est passee de 20 a
# 21 — `ssh.py:sshd_allow_user` l'a rejointe en corrigeant E-214 — et **rien ici
# ne l'a dit**. C'est le Lead qui me l'a signale.
#
# *Une liste de routes est une photographie, et le chantier la perime lui-meme.*
# La reponse a cela n'est pas « ne pas figer » : c'est figer, et RELIRE a chaque
# changement.
VERDICT_CONDITIONNEL_CONNU = {
    ('cve.py', 'cve_test_connection'),
    ('fail2ban.py', 'fail2ban_ban_all_servers'),
    ('fail2ban.py', 'fail2ban_install_all'),
    ('fail2ban.py', 'fail2ban_install_route'),
    ('fail2ban.py', 'fail2ban_restart'),
    ('graylog.py', 'delete_template'),
    ('graylog.py', 'deploy'),
    ('graylog.py', 'test_forward'),
    ('services.py', 'services_disable'),
    ('services.py', 'services_enable'),
    ('services.py', 'services_restart'),
    ('services.py', 'services_start'),
    ('services.py', 'services_stop'),
    ('ssh.py', 'deploy_platform_key'),
    ('ssh.py', 'deploy_service_account'),
    ('ssh.py', 'revoke_service_account'),
    # Arrivee le 2026-08-27 en corrigeant E-214, et personne ne l'a vue entrer.
    ('ssh.py', 'sshd_allow_user'),
    ('wazuh.py', 'delete_rule'),
    ('wazuh.py', 'install_all'),
    ('wazuh.py', 'restart_agent'),
    ('wazuh.py', 'uninstall'),
}


def test_l_analyse_a_bien_vu_le_backend(routes):
    """L'INSTRUMENT D'ABORD. Une enumeration vide rend toute propriete
    universelle vraie."""
    assert RACINE.is_dir(), f'repertoire des routes introuvable : {RACINE}'
    assert len(routes) >= PLANCHER_ROUTES, (
        f'{len(routes)} routes lues — sous le plancher : le chemin a change, ou '
        "l'analyse ne voit plus les decorateurs")


def test_le_compte_des_familles_se_reconstitue(routes):
    """UN TOTAL QU'ON NE SAIT PAS RECONSTITUER N'EST PAS UN TOTAL.

    Chaque route tombe dans exactement une famille. Si la somme cesse d'egaler le
    nombre de routes, une famille sort du classement sans etre comptee — et une
    route non classee est une route dont personne ne sait ce qu'elle rend.
    """
    par_famille = {f: sum(1 for r in routes if r['famille'] == f)
                   for f in ('dur', 'conditionnel', 'jamais')}

    assert sum(par_famille.values()) == len(routes), (
        f'{par_famille} ne reconstitue pas {len(routes)} routes')


def test_aucune_route_NEUVE_ne_rejoint_la_famille_du_200_menteur(routes):
    """L'INVARIANT.

    Une route qui rejoint cette famille rend un refus **indiscernable d'une
    reussite pour qui ne lit que le statut**. Ses appelants doivent alors etre
    relus — et rien ne change chez eux, donc ils sont invisibles au diff.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['famille'] == 'dur'}
    nouvelles = sorted(reelles - VERDICT_A_200_CONNU)

    assert not nouvelles, (
        'Des routes rendent DESORMAIS 200 avec `success: false` :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in nouvelles)
        + "\n\nCe n'est pas un defaut en soi — c'est un CHANGEMENT DE CONTRAT.\n"
          "Relire les appelants de ces routes dans `laravel/public/js/` : ceux qui\n"
          "ne testent que `reponse.ok` presenteront desormais un refus comme une\n"
          "reussite. Voir `docs/migration/QA-APPELANTS.md`.")


def test_les_connues_sont_TOUJOURS_dans_la_famille(routes):
    """LA GARDE SYMETRIQUE.

    Une entree qui n'est plus trouvee a DEUX causes opposees, et une seule est une
    bonne nouvelle : la route a ete corrigee (son refus porte enfin un statut), ou
    l'INSTRUMENT ne la voit plus. Sans cette assertion, la liste se viderait en
    silence et l'invariant passerait au vert en ne mesurant plus rien.

    C'est la lecon de `test_invariant_machine_id.py`, ou deux entrees sur trois
    n'etaient plus trouvees pour ces deux raisons exactement.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['famille'] == 'dur'}
    disparues = sorted(VERDICT_A_200_CONNU - reelles)

    assert not disparues, (
        "Des routes connues ne rendent plus 200 avec `success: false` :\n  "
        + '\n  '.join(f'{f}:{n}' for f, n in disparues)
        + "\n\nDEUX causes opposees :\n"
          "  - la route a ete CORRIGEE (son refus porte un statut) : retirer\n"
          "    l entree, en ecrivant la raison ;\n"
          "  - l INSTRUMENT ne la voit plus : `_famille` a cesse de reconnaitre une\n"
          "    forme de retour, et elle en manque alors d autres.")


def test_aucune_route_NEUVE_ne_rejoint_la_famille_CONDITIONNELLE(routes):
    """`return jsonify({'success': rc == 0})` rend **200 quoi qu'il arrive**.

    Une lecture rapide n'y voit pas de refus ; un appelant qui teste `.ok` n'en
    voit pas davantage. C'est la meme classe de risque que `dur`, sans en avoir
    la forme — et c'est la plus nombreuse des deux.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['famille'] == 'conditionnel'}
    nouvelles = sorted(reelles - VERDICT_CONDITIONNEL_CONNU)

    assert not nouvelles, (
        'Des routes rendent DESORMAIS un `success` calcule a 200 :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in nouvelles)
        + "\n\nRelire leurs appelants : ceux qui ne testent que `reponse.ok`\n"
          'presenteront un refus comme une reussite.')


def test_les_CONDITIONNELLES_connues_le_sont_toujours(routes):
    """La garde symetrique, quatrieme fois dans ce depot.

    Une sortie a deux causes opposees : la route a ete corrigee (son refus porte
    un statut), ou `_famille` a cesse de reconnaitre une forme — et elle en manque
    alors d'autres. Les deux se distinguent en LISANT.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['famille'] == 'conditionnel'}
    disparues = sorted(VERDICT_CONDITIONNEL_CONNU - reelles)

    assert not disparues, (
        'Des routes connues ne rendent plus un `success` calcule a 200 :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in disparues)
        + '\nCorrigee, ou instrument devenu aveugle : lire pour trancher.')



def test_aucune_route_NEUVE_ne_rend_un_flux_sans_etre_relevee(routes):
    """UNE ROUTE QUI DEVIENT UN FLUX CHANGE DE CONTRAT PLUS FORT QUE LES AUTRES.

    Ses appelants ne doivent pas seulement lire `success` — **ils doivent cesser
    d'appeler `r.json()`**, qui leve sur du JSON-lines. Un appelant inchange ne
    lit alors plus rien du tout, et son ecran l'annonce comme une reussite.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['flux']}
    nouvelles = sorted(reelles - FLUX_CONNUS)

    assert not nouvelles, (
        'Des routes rendent DESORMAIS un flux :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in nouvelles)
        + "\n\nLeurs appelants doivent lire le CORPS ligne par ligne. Un `r.json()`\n"
          "sur du JSON-lines leve a chaque fois, l exception est avalee, et le compte\n"
          "rendu n est pas mal lu : il n est pas lu du tout.")


def test_les_flux_connus_en_sont_TOUJOURS(routes):
    """LA GARDE SYMETRIQUE, troisieme fois dans ce depot.

    Une route qui quitte la famille l a quittee pour une raison — ou l instrument
    ne la voit plus. Les deux se distinguent en LISANT, jamais en supposant.
    """
    reelles = {(r['fichier'], r['nom']) for r in routes if r['flux']}
    disparues = sorted(FLUX_CONNUS - reelles)

    assert not disparues, (
        'Des routes connues ne rendent plus un flux :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in disparues)
        + "\n\nDEUX causes opposees : la route a change de forme, ou `_rend_un_flux`\n"
          'a cesse de reconnaitre la sienne — et elle en manque alors d autres.')
