"""
test_invariant_machine_id.py — L'INVARIANT DE `@require_machine_access`.

    Sur une route qui porte `@require_machine_access`, l'identifiant de machine
    doit etre OBLIGATOIRE. S'il est facultatif, la route doit porter une
    autorisation PROPRE — `@require_role` ou `@require_permission`.

POURQUOI CET INVARIANT PLUTOT QUE DIX TESTS UNITAIRES
-----------------------------------------------------
`routes/helpers.py` fait, dans le decorateur :

    denied = [mid for mid in ids if not check_machine_access(mid)]
    if denied: -> 403

**`ids` vide => `denied` vide => le garde passe.** Un identifiant facultatif rend
donc la garde INERTE, silencieusement, en rendant un jeu de donnees parfaitement
coherent. C'est E-211, et ce n'est pas un defaut de ce decorateur : il LIT bien
`request.args` autant que le corps (`data.get(...) or request.args.get(...)`).
**Ce n'est pas la PROVENANCE du parametre qui le neutralise, c'est son caractere
FACULTATIF.** Chercher le defaut dans le decorateur enverrait corriger ce qui n'a
rien a corriger.

Un test par route mesurerait trois cas connus ; l'invariant mesure la CLASSE
entiere, et il rougira le jour ou une route neuve rejoindra la classe.

CE QUE CE TEST NE FAIT PAS, ET C'EST DELIBERE
---------------------------------------------
Il **ne s'appuie sur aucun resolveur partage**. Les resolveurs du backend font
`SELECT ... WHERE id = %s` : ils LISENT une machine, ils n'AUTORISENT rien. Les
suivre reviendrait a compter une lecture pour une garde.

Il **n'importe aucun module du backend**. `import server` lance un ordonnanceur —
`start_scheduler()` au niveau module, sans garde `if __name__` — et `py_compile`
passerait sur un nom jamais importe. On lit donc l'ARBRE SYNTAXIQUE : c'est la
seule facon de mesurer une structure sans executer ce qu'elle declare.

LA FORME DE L'ASSERTION — regression, pas absolu
------------------------------------------------
Le corpus porte un PASSE : trois routes sont deja dans cet etat, dont **deux
dedouanees par la lecture de leur corps**. Une assertion absolue rougirait sur un
etat qu'on ne compte pas corriger, et **une garde qui alarme en permanence finit
desactivee** — ce jour-la elle n'attrape plus rien. On mesure donc l'ECART a un
etat connu, nomme, et justifie ligne par ligne.
"""
import ast
import pathlib

import pytest

RACINE = pathlib.Path(__file__).resolve().parent.parent / 'routes'

# Les noms sous lesquels un identifiant de machine arrive dans une requete.
CLES = ('machine_id', 'server_id', 'machine_ids', 'server_ids')

# ── L'ETAT CONNU, ET CHAQUE ENTREE PORTE SA RAISON ────────────────────────
#
# Mesure du releve par arbre syntaxique (`RELEVE-GARDES-BACKEND.md` §3), relue
# corps par corps. Deux sont DEDOUANEES : leur code borne le perimetre par un
# autre moyen que le decorateur. La troisieme est un ecart REEL et etroit.
FACULTATIVES_CONNUES = {
    # DEDOUANEE : `machine_id` est optionnel, mais le corps borne au perimetre
    # du compte (`user_machine_access` + `get_current_user`). L'absence de garde
    # du decorateur ne cree pas de trou.
    ('docker.py', 'docker_results'),
    # ── (`updates.py`, `update_zabbix`) EST RETIREE — 2026-09-04 ────────────
    #
    # Elle etait DEDOUANEE : redirection 307 vers `/supervision/zabbix/deploy`,
    # qui porte role(2) + permission + machine_access, et le 307 preserve
    # methode et corps — les gardes s'appliquaient A L'ARRIVEE.
    #
    # `07a530f` (E-389, « 13 routes POST sans role ni permission ») lui a pose
    # `@require_role(2)`. Elle a donc une autorisation PROPRE et sort de la
    # classe mesuree ici : la garder ferait rougir le premier test du fichier,
    # qui asserte que ce releve ne nomme que des routes SANS autorisation.
    #
    # Retiree en ECRIVANT LA RAISON, comme le message du troisieme test le
    # prescrit — c'est la premiere des deux causes qu'il demande de trancher :
    # la route a ete CORRIGEE, elle n'a pas disparu.
    # ── E-211 (`ssh_audit.py`, `ssh_audit_policies_get`) EST RETIREE ─────────
    #
    # Elle porte desormais `@require_permission('can_audit_ssh')` : la route a
    # une autorisation PROPRE, donc elle sort de la classe mesuree ici. La garder
    # « tant que la mesure ne l'a pas confirme EN SERVICE » etait une intention
    # juste et un mecanisme faux : cette liste ne mesure pas le service, elle
    # mesure le DISQUE. Une entree qui ne peut plus jamais correspondre est un
    # residu — et un residu masque une regression du meme nom.
    #
    # Ce que le service doit confirmer se mesure ailleurs : au navigateur, ou par
    # un rejeu apres redemarrage. Pas ici.
}

# En dessous de ce seuil, l'analyse n'a rien vu : c'est l'INSTRUMENT qui est
# casse, pas le code. Une enumeration qui rend le vide satisfait toutes les
# proprietes universelles.
PLANCHER_ROUTES_GARDEES = 100


def _nom_decorateur(noeud):
    """Rend le nom d'un decorateur, qu'il soit appele ou non."""
    cible = noeud.func if isinstance(noeud, ast.Call) else noeud
    if isinstance(cible, ast.Name):
        return cible.id
    if isinstance(cible, ast.Attribute):
        return cible.attr
    return ''


def _lit_un_identifiant(fn):
    """La fonction lit-elle un identifiant de machine dans la requete ?"""
    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and n.value in CLES:
            return True
    return False


def _refuse_si_absent(fn):
    """La fonction REFUSE-t-elle quand l'identifiant manque ?

    ══ QUATRE FORMES, TROUVEES PAR LA MESURE ════════════════════════════════

    Une premiere redaction ne cherchait que `if not <var>` et accusait **18**
    routes la ou le releve en compte 3. Chaque elargissement est venu d'une
    lecture, jamais d'une supposition :

      1. `if not machine_id: return 400`                    — le refus explicite ;
      2. `validate_machine_id(data.get('machine_id'))`      — `None`, `''` et `0`
         levent `ValueError` ;
      3. `..., err = resolve_ssh_creds(data)` puis `if err:` — `resolve_ssh_creds({})`
         rend `err = 'machine_id requis.'` ;
      4. `if not machine_id or not username:`               — un `BoolOp`.

    **Enumerer des formes est sans fin.** On generalise : toute variable NOURRIE
    par une lecture d'identifiant — deballage du tuple d'un resolveur compris —
    mentionnee dans un `if` dont une branche REND ou LEVE, vaut refus.

    ══ ET CETTE GENERALISATION EXONERE A TORT — MESURE LE 2026-08-28 ═════════

    `docker.py:docker_results` etait classee « exige l'identifiant ». Elle ne
    l'exige pas : son `machine_id` est OPTIONNEL, et le `return` que la regle
    voyait vit dans la branche **POSITIVE** —

        if machine_id:
            try:    params.append(int(machine_id))
            except: return jsonify(...), 400     <-- le `return` que la regle voyait
        else:
            ...    # identifiant ABSENT : la route CONTINUE

    Le `return` y traite un identifiant **present et mal forme**. Absent, la
    route poursuit. La regle mesurait la presence d'un `return` sous un `if` qui
    MENTIONNE l'identifiant ; la propriete est que ce `return` soit sur le chemin
    de l'**ABSENCE**. C'est un faux PASS, et du cote qui EXONERE — donc du cote
    qui ne se relit pas.

    LA PARADE EST ETROITE, ET C'EST DELIBERE. Resserrer en exigeant un test
    d'absence explicite a ete mesure : **62 routes** basculaient, parce que la
    troisieme forme (`if err:`) est un test de PRESENCE — d'une erreur, pas d'un
    identifiant. On n'ecarte donc QUE la forme fautive : `if <identifiant>:` en
    polarite positive, ou seul un `return` dans le `else` vaudrait refus.

    ⚠ CE QUE `resolve_ssh_creds` PROUVE, ET CE QU'IL NE PROUVE PAS. Il EXIGE
    l'identifiant — la propriete mesuree ici. Il n'AUTORISE rien : il fait
    `SELECT ... WHERE id = %s`, sans `check_machine_access`. S'appuyer sur lui
    pour l'exigence est juste ; pour l'acces, ce serait compter une lecture pour
    une garde.

    Le sens de l'erreur residuelle est celui qui coute le moins : cette fonction
    peut encore rendre `False` sur une route qui exige bien l'identifiant — donc
    ACCUSER a tort, ce qui se relit — mais elle ne peut plus EXONERER une route
    dont l'identifiant est facultatif.
    """
    # FORME 2 : le validateur partage leve quand l'identifiant manque.
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and _nom_decorateur(n) == 'validate_machine_id':
            return True

    # Deux familles de variables, et elles ne se testent PAS dans la meme
    # polarite : l'identifiant se teste par son ABSENCE, l'erreur d'un resolveur
    # par sa PRESENCE.
    identifiants, erreurs = set(), set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Assign):
            continue
        par_resolveur = (isinstance(n.value, ast.Call)
                         and _nom_decorateur(n.value).endswith('resolve_ssh_creds'))
        if not (par_resolveur or _lit_un_identifiant(n.value)):
            continue
        cible = erreurs if par_resolveur else identifiants
        for c in n.targets:
            for x in ast.walk(c):
                if isinstance(x, ast.Name):
                    cible.add(x.id)

    nourries = identifiants | erreurs
    if not nourries:
        return False

    for n in ast.walk(fn):
        if not isinstance(n, ast.If):
            continue
        mentionnees = {x.id for x in ast.walk(n.test) if isinstance(x, ast.Name)}
        if not (mentionnees & nourries):
            continue

        # `if <identifiant>:` — le corps traite l'identifiant PRESENT. Seul un
        # `return` dans le `else` porterait sur son absence.
        polarite_positive = (isinstance(n.test, ast.Name)
                             and n.test.id in identifiants
                             and n.test.id not in erreurs)
        if polarite_positive:
            if any(isinstance(x, (ast.Return, ast.Raise))
                   for b in n.orelse for x in ast.walk(b)):
                return True
            continue

        if any(isinstance(x, (ast.Return, ast.Raise)) for x in ast.walk(n)):
            return True
    return False


def _routes():
    """Toutes les routes du backend, avec leurs decorateurs — par AST."""
    trouvees = []
    for fichier in sorted(RACINE.glob('*.py')):
        arbre = ast.parse(fichier.read_text(encoding='utf-8'), filename=str(fichier))
        for fn in ast.walk(arbre):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decos = [_nom_decorateur(d) for d in fn.decorator_list]
            if not any(d == 'route' for d in decos):
                continue
            trouvees.append({
                'fichier': fichier.name,
                'nom': fn.name,
                'decorateurs': decos,
                'lit': _lit_un_identifiant(fn),
                'refuse': _refuse_si_absent(fn),
            })
    return trouvees


@pytest.fixture(scope='module')
def routes():
    return _routes()


def test_l_analyse_a_bien_vu_le_backend(routes):
    """L'INSTRUMENT D'ABORD. Un ensemble vide rend toute propriete universelle
    vraie : sans ce controle, l'invariant passerait au vert le jour ou le chemin
    des routes changerait — exactement le `glob` depuis un conteneur qui ne
    monte pas le repertoire vise."""
    assert RACINE.is_dir(), f'repertoire des routes introuvable : {RACINE}'
    assert len(routes) >= 150, f'seulement {len(routes)} routes lues — analyse creuse'
    gardees = [r for r in routes if 'require_machine_access' in r['decorateurs']]
    assert len(gardees) >= PLANCHER_ROUTES_GARDEES, (
        f'{len(gardees)} routes portent `@require_machine_access` — '
        'sous le plancher : le decorateur a ete renomme, ou l analyse ne le voit plus')


def test_machine_id_obligatoire_sur_les_routes_gardees(routes):
    """L'INVARIANT.

    Une route qui porte le decorateur et dont l'identifiant est FACULTATIF ne
    l'exige pas, donc le decorateur n'y refuse rien. Elle doit alors porter une
    autorisation PROPRE.
    """
    sans_objet = []
    for r in routes:
        if 'require_machine_access' not in r['decorateurs']:
            continue
        if r['refuse']:
            continue                      # l'identifiant est exige : le garde mord
        propre = any(d in ('require_role', 'require_permission') for d in r['decorateurs'])
        if propre:
            continue                      # une autorisation propre couvre le chemin sans identifiant
        sans_objet.append((r['fichier'], r['nom']))

    nouvelles = sorted(set(sans_objet) - FACULTATIVES_CONNUES)
    assert not nouvelles, (
        'Routes NEUVES ou `@require_machine_access` est sans objet et qui ne portent '
        'aucune autorisation propre :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in nouvelles)
        + "\n\n`ids` vide => `denied` vide => le garde passe (helpers.py). Exiger "
          "l'identifiant, ou poser `@require_role` / `@require_permission`.")


def test_les_connues_sont_toujours_des_routes_reelles(routes):
    """LA LISTE CONNUE DOIT VIEILLIR AVEC LE CODE.

    Une entree qui ne designe plus aucune route est un residu : elle masquerait
    une regression portant le meme nom, et elle laisserait croire a un etat
    mesure. **Une liste ecrite a la main vieillit ; on la fait donc verifier par
    le code qu'elle decrit.**
    """
    reelles = {(r['fichier'], r['nom']) for r in routes}
    fantomes = sorted(FACULTATIVES_CONNUES - reelles)
    assert not fantomes, (
        'Entrees de `FACULTATIVES_CONNUES` qui ne designent plus aucune route :\n  '
        + '\n  '.join(f'{f}:{n}' for f, n in fantomes)
        + '\nRetirer l entree, ou corriger le nom.')


def test_les_connues_sont_TOUJOURS_TROUVEES(routes):
    """LA GARDE SYMETRIQUE, ET ELLE MANQUAIT.

    L'invariant asserte que rien de NEUF n'entre dans la classe. Rien n'assertait
    que les entrees CONNUES y sont encore. Une liste qui ne peut plus correspondre
    passe donc au vert en ne mesurant plus rien — et c'est dans cet etat que ce
    fichier a ete remis : **deux de ses trois entrees n'etaient plus trouvees**,
    pour deux raisons OPPOSEES.

      `ssh_audit_policies_get`  CORRIGEE — elle porte une autorisation propre.
                                L'entree etait un residu : retiree.
      `docker_results`          NON corrigee — c'est l'INSTRUMENT qui l'exonerait
                                a tort. Corrige dans `_refuse_si_absent`.

    **Une seule des deux disparitions etait une bonne nouvelle**, et rien ne les
    distinguait. C'est exactement pourquoi il faut regarder : une liste qui se
    raccourcit se relit aussi attentivement qu'une liste qui s'allonge.
    """
    trouvees = set()
    for r in routes:
        if 'require_machine_access' not in r['decorateurs']:
            continue
        if r['refuse']:
            continue
        if any(d in ('require_role', 'require_permission') for d in r['decorateurs']):
            continue
        trouvees.add((r['fichier'], r['nom']))

    disparues = sorted(FACULTATIVES_CONNUES - trouvees)
    assert not disparues, (
        "Des entrees connues ne sont plus trouvees par l'invariant :\n  "
        + '\n  '.join(f'{f}:{n}' for f, n in disparues)
        + "\n\nDEUX causes opposees, et il faut trancher laquelle :\n"
          "  - la route a ete CORRIGEE (autorisation propre, ou identifiant\n"
          "    desormais exige) : retirer l entree, en ecrivant la raison ;\n"
          "  - l INSTRUMENT ne la voit plus : `_refuse_si_absent` exonere a tort,\n"
          "    et il exonere alors aussi tout ce qui lui ressemble.")
