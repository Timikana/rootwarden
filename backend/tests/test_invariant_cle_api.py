"""
test_invariant_cle_api.py — L'INVARIANT DE `@require_api_key`.

    Toute route du backend doit porter `@require_api_key`. Les exceptions sont
    NOMMEES, chacune avec l'authentification alternative qui la justifie.

POURQUOI UN INVARIANT ET NON UNE REGLE SEMGREP
----------------------------------------------
Cette propriete etait une regle semgrep — `rw-flask-route-without-api-key`. Elle
a echoue deux fois, et la seconde fois est la lecon :

  1. **son motif ne compilait pas** : un `...` SEUL entre deux decorateurs et le
     `def`, position ou Python n'admet que des lignes commencant par `@`.
     Consequence : la regle n'a JAMAIS rien garde depuis son ecriture le
     2026-05-19 — 19 executions de CI, zero succes ;
  2. **reparee, elle rendait 3 faux positifs PERMANENTS.** Sur 230 routes, 3
     n'ont pas la cle — et les trois sont legitimes, documentees a leur site.

**La propriete etait vraie ; c'est l'INSTRUMENT qui etait faux.** Un moteur de
motifs ne sait pas porter une liste d'exceptions ARGUMENTEES, ni n'asserter que
l'ECART a un etat connu. Il ne sait dire que « voici toutes les occurrences »,
ce qui, sur un corpus qui porte un passe, alarme en permanence — **et une garde
qui alarme toujours finit desactivee, ce jour-la elle n'attrape plus rien.**

CE QUE CE FICHIER MESURE
------------------------
L'ECART a un etat connu, nomme et justifie, sur le modele de
`test_invariant_machine_id.py` — plancher d'instrument compris.

Il **n'importe aucun module du backend** : `import server` lance un
ordonnanceur au niveau module. On lit l'arbre syntaxique.
"""
import ast
import pathlib

import pytest

RACINE = pathlib.Path(__file__).resolve().parent.parent / 'routes'

# ── LE PLANCHER D'INSTRUMENT ──────────────────────────────────────────────
#
# Mesure du 2026-09-04 : 230 routes, dont 227 portent `@require_api_key`.
# Sous ce plancher, ce n'est pas « il n'y a plus d'ecart » — c'est que
# l'ANALYSE n'a rien vu : `glob` sur un repertoire absent, decorateur renomme,
# ou fichier de routes deplace. **Un ensemble vide rend toute propriete
# universelle vraie**, et c'est la panne qui passe au vert.
PLANCHER_ROUTES = 150
PLANCHER_AVEC_CLE = 200

# ── L'ETAT CONNU, ET CHAQUE ENTREE PORTE SON AUTHENTIFICATION ─────────────
#
# Les trois ont ete LUES a leur site avant d'etre dedouanees. Une route nommee
# `update_security_exec` sans cle d'API etait le candidat le plus inquietant du
# lot : c'est une authentification ALTERNATIVE, documentee dans son docstring.
SANS_CLE_CONNUES = {
    # Jeton HMAC machine-to-machine (`X-Update-Token`), borne au `machine_id` et
    # signe avec `SECRET_KEY`. Appelee par un cron SUR LA MACHINE DISTANTE, qui
    # ne detient pas la cle d'API du portail.
    ('updates.py', 'update_security_exec'),
    # Signature Slack OU jeton partage. Le docstring le dit : « PAS de
    # require_api_key (Slack/Teams ne fournissent pas la cle) ». Bornee en amont
    # par `Config.CHATOPS_ENABLED`.
    ('chatops.py', 'chatops_command'),
    # Sonde de vie : rend une chaine statique, ne lit rien, n'ecrit rien,
    # ne joint aucune machine.
    ('monitoring.py', 'test'),
}


def _nom_decorateur(d):
    if isinstance(d, ast.Call):
        return _nom_decorateur(d.func)
    if isinstance(d, ast.Name):
        return d.id
    if isinstance(d, ast.Attribute):
        return d.attr
    return ''


def _routes():
    """Toutes les routes du backend et leurs decorateurs — par AST."""
    trouvees = []
    for fichier in sorted(RACINE.glob('*.py')):
        arbre = ast.parse(fichier.read_text(encoding='utf-8'), filename=str(fichier))
        for fn in ast.walk(arbre):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decos = [_nom_decorateur(d) for d in fn.decorator_list]
            if 'route' not in decos:
                continue
            trouvees.append({'fichier': fichier.name, 'nom': fn.name, 'decorateurs': decos})
    return trouvees


@pytest.fixture(scope='module')
def routes():
    return _routes()


def test_l_analyse_a_bien_vu_le_backend(routes):
    """L'INSTRUMENT D'ABORD, et c'est lui qui distingue « aucun ecart » de
    « l'analyse n'a rien vu »."""
    assert RACINE.is_dir(), f'repertoire des routes introuvable : {RACINE}'
    assert len(routes) >= PLANCHER_ROUTES, (
        f'{len(routes)} routes lues — sous le plancher : analyse creuse')
    avec = [r for r in routes if 'require_api_key' in r['decorateurs']]
    assert len(avec) >= PLANCHER_AVEC_CLE, (
        f'{len(avec)} routes portent `@require_api_key` — sous le plancher : '
        'le decorateur a ete renomme, ou l analyse ne le voit plus')


def test_toute_route_porte_la_cle_api(routes):
    """L'INVARIANT — l'ECART, pas l'absolu."""
    sans = {(r['fichier'], r['nom']) for r in routes
            if 'require_api_key' not in r['decorateurs']}
    nouvelles = sorted(sans - SANS_CLE_CONNUES)
    assert not nouvelles, (
        'Routes NEUVES sans `@require_api_key` :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in nouvelles)
        + "\n\nPoser `@require_api_key`, ou — si la route porte une "
          "authentification ALTERNATIVE — l ajouter a `SANS_CLE_CONNUES` "
          "EN ECRIVANT LAQUELLE. Une exception sans sa raison est un trou "
          "qui a l air d une decision.")


def test_les_connues_sont_toujours_des_routes_reelles(routes):
    """UNE LISTE ECRITE A LA MAIN VIEILLIT — on la fait verifier par le code
    qu'elle decrit. Une entree qui ne designe plus aucune route est un residu,
    et un residu masque une regression portant le meme nom."""
    reelles = {(r['fichier'], r['nom']) for r in routes}
    fantomes = sorted(SANS_CLE_CONNUES - reelles)
    assert not fantomes, (
        'Entrees de `SANS_CLE_CONNUES` qui ne designent plus aucune route :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in fantomes)
        + '\nRetirer l entree, ou corriger le nom.')


def test_les_connues_sont_TOUJOURS_TROUVEES(routes):
    """LA GARDE SYMETRIQUE.

    L'invariant asserte que rien de NEUF n'entre dans la classe. Sans celle-ci,
    rien n'asserterait que les CONNUES y sont encore — et une liste qui ne peut
    plus correspondre passe au vert en ne mesurant plus rien.

    **Deux causes OPPOSEES, et il faut trancher laquelle :** la route a gagne
    `@require_api_key` (bonne nouvelle : retirer l entree en ecrivant pourquoi),
    ou l'analyse ne la voit plus (l instrument est casse, et il exonere alors
    aussi tout ce qui lui ressemble). **Une seule des deux est une bonne
    nouvelle, et rien ne les distingue sans regarder.**
    """
    sans = {(r['fichier'], r['nom']) for r in routes
            if 'require_api_key' not in r['decorateurs']}
    disparues = sorted(SANS_CLE_CONNUES - sans)
    assert not disparues, (
        "Des entrees connues ne sont plus trouvees par l'invariant :\n  "
        + '\n  '.join(f'{f}:{n}' for f, n in disparues)
        + '\n\nDEUX causes opposees — trancher laquelle avant de modifier la liste.')
