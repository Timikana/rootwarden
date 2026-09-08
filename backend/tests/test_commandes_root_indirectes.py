r"""
test_commandes_root_indirectes.py - la forme que la regle semgrep NE VOIT PAS.

┌─ LA CLASSE QUE CE TEST GARDE ────────────────────────────────────────────────┐
│ `rw-shell-fstring-execute-as-root` n'apparie que la f-string ECRITE EN LIGNE  │
│ dans l'appel :                                                                │
│     execute_as_root(client, f"rm {chemin}", mdp)        <- VUE                │
│     cmd = f"rm {chemin}"                                                      │
│     execute_as_root(client, cmd, mdp)                   <- INVISIBLE          │
│                                                                               │
│ Les deux formes portent exactement le meme risque. Le cliquet des trouvailles │
│ est a ZERO depuis le 2026-09-09 : ce zero ne veut donc pas dire « zero site », │
│ il veut dire « zero site VISIBLE par cet instrument ». Ce test mesure l'autre  │
│ moitie.                                                                       │
│                                                                               │
│ Le site de la vulnerabilite corrigee le 2026-09-08 — `routes/updates.py:607`, │
│ qui passe `command` — est precisement dans la moitie invisible.               │
└──────────────────────────────────────────────────────────────────────────────┘

POURQUOI UN TEST ET PAS UNE REGLE SEMGREP. La tentative d'ecrire la forme
sequencee en regle (`42dcb5d7`) a fait sortir semgrep en code 7 SANS SORTIE —
configuration refusee — et a mis a terre les DEUX jobs de regles custom
(`9c6e901e` l'annule). Iterer dessus demande un juge semgrep local, absent de
cet hote. Un balayage AST, lui, s'eprouve ici et maintenant sur des sources
forgees.

L'AST PLUTOT QU'UN MOTIF, ET CE N'EST PAS UN GOUT. Trois relevés successifs de
cette meme classe ont sur- ou sous-compte, chaque fois pour une raison de
FORME :
  fenetre de 3 lignes   un appel portant une chaine NUE se voyait crediter la
                        f-string de l'appel SUIVANT           -> 20 au lieu de 18
  portee MODULE         un appel se voyait crediter un binding 442 lignes plus
                        loin, dans une autre fonction          -> 31 au lieu de 27
  test `isinstance(valeur, JoinedStr)`
                        `f"..{x}" if c else ""` est un `IfExp`, pas un
                        `JoinedStr` : 5 sites de `updates.py` DISPARAISSAIENT
                                                               -> 27 au lieu de 33
Les deux premieres erreurs ALARMENT, la troisieme DEDOUANE — et c'est celle-la
qu'aucune relecture n'attrape, parce qu'un chiffre plus bas ressemble a un
progres.

⚠ CE QUE CE TEST NE COUVRE PAS, ecrit plutot que suppose :
  · une commande passee a `execute_as_root` via un ATTRIBUT (`self.cmd`) ou un
    indice (`d['cmd']`) : seule la forme `Name` est suivie ;
  · une f-string qui traverse un APPEL intermediaire (`f(x)` qui rend la
    commande) : aucune analyse inter-procedurale ;
  · les appels ou `execute_as_root` est atteint par un attribut
    (`mod.execute_as_root`).
Ces trois formes rendraient un faux zero. Le cliquet ne les voit pas, donc il
ne les garde pas — il ne les cache pas non plus.
"""

import ast
import collections
import os

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── LE CLIQUET ────────────────────────────────────────────────────────────────
# Releve le 2026-09-09 a 01:45 CEST, par ce meme balayage, sur `backend/**.py`
# hors `tests/`. Il ECHOUE si le compte CROIT, il informe s'il descend.
# Remesure :  python3 backend/tests/test_commandes_root_indirectes.py
REFERENCE = 34


def _interpolee(noeud) -> bool:
    """Le sous-arbre contient-il une f-string INTERPOLEE, ou qu'elle soit ?

    Recursif A DESSEIN. Tester `isinstance(valeur, JoinedStr)` manque le
    ternaire, la concatenation, le `.join(...)`, l'affectation augmentee — soit
    5 des 33 sites, tous dans `routes/updates.py`, et tous passant une commande
    root construite avec une entree.
    """
    for n in ast.walk(noeud):
        if isinstance(n, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in n.values):
                return True
    return False


def _noms_cibles(noeud):
    """Les noms lies par une cible d'affectation, `a, cmd = ...` compris."""
    if isinstance(noeud, ast.Name):
        yield noeud.id
    elif isinstance(noeud, (ast.Tuple, ast.List)):
        for e in noeud.elts:
            yield from _noms_cibles(e)


def sites_indirects(source: str):
    """Rend [(ligne_appel, variable, ligne_du_binding)] tries.

    Un site compte si TOUTES ces conditions tiennent :
      · l'appelee est `execute_as_root` atteinte par un NOM ;
      · aucun argument n'est une f-string en ligne (sinon semgrep la voit deja,
        et le compter ici ferait un doublon avec le cliquet) ;
      · un argument est un NOM lie, DANS LA MEME FONCTION et AVANT l'appel, a
        une valeur contenant une f-string interpolee.
    """
    arbre = ast.parse(source)
    trouves = []
    non_resolus = []
    # carte des portees englobantes, pour que l'aveu ne denonce pas une fermeture
    parents = {}
    for pere in ast.walk(arbre):
        if isinstance(pere, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for fils in ast.walk(pere):
                if fils is not pere and isinstance(fils, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    parents.setdefault(fils, pere)
    for fonction in ast.walk(arbre):
        if not isinstance(fonction, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        teintes = collections.defaultdict(list)
        # Les noms connus incluent les parametres des portees ENGLOBANTES : une
        # fonction imbriquee voit `root_password` de sa mere. Sans ca l'aveu
        # denonce des fermetures parfaitement ordinaires, et un aveu qui crie
        # tout le temps ne se lit plus.
        connus = {p.arg for p in ast.walk(fonction) if isinstance(p, ast.arg)}
        englobante = parents.get(fonction)
        while englobante is not None:
            connus |= {p.arg for p in englobante.args.args + englobante.args.kwonlyargs}
            if englobante.args.vararg:
                connus.add(englobante.args.vararg.arg)
            if englobante.args.kwarg:
                connus.add(englobante.args.kwarg.arg)
            connus |= {n.id for x in ast.walk(englobante) if isinstance(x, ast.Assign)
                       for c in x.targets for n in ast.walk(c) if isinstance(n, ast.Name)}
            englobante = parents.get(englobante)
        # DEUX passes : la seconde propage `for cmd in cmds` quand `cmds` n'est
        # teinte qu'apres la premiere. Sans elle, la liaison indirecte par une
        # variable intermediaire echappe — et elle echappe DANS LE SENS QUI
        # DEDOUANE.
        for _ in range(2):
            for n in ast.walk(fonction):
                valeur = cibles = ligne = None
                if isinstance(n, ast.Assign):
                    valeur, cibles, ligne = n.value, n.targets, n.lineno
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    valeur, cibles, ligne = n.value, [n.target], n.lineno
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    # Une cible de boucle n'est PAS un `ast.Assign`. Signalee par
                    # `gestion-ssh-key-5f` le 2026-09-09 : `fail2ban_manager.py`
                    # porte un `for cmd in cmds:` ou `cmds` est une liste de
                    # TROIS commandes root. Mon compte de 33 en cachait une.
                    valeur, cibles, ligne = n.iter, [n.target], n.lineno
                elif isinstance(n, ast.comprehension):
                    valeur, cibles, ligne = n.iter, [n.target], getattr(n.target, 'lineno', 0)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        if item.optional_vars is None:
                            continue
                        for nom in _noms_cibles(item.optional_vars):
                            connus.add(nom)
                            if _interpolee(item.context_expr) and n.lineno not in teintes[nom]:
                                teintes[nom].append(n.lineno)
                    continue
                if valeur is None:
                    continue
                # teinte DIRECTE, ou TRANSITIVE : la valeur est un nom deja teinte
                teinte = _interpolee(valeur) or (isinstance(valeur, ast.Name) and valeur.id in teintes)
                for cible in cibles:
                    for nom in _noms_cibles(cible):
                        connus.add(nom)
                        if teinte and ligne not in teintes[nom]:
                            teintes[nom].append(ligne)
        for n in ast.walk(fonction):
            if not isinstance(n, ast.Call):
                continue
            if not (isinstance(n.func, ast.Name) and n.func.id == 'execute_as_root'):
                continue
            if any(isinstance(a, ast.JoinedStr) for a in n.args):
                continue
            for a in n.args:
                if not isinstance(a, ast.Name):
                    continue
                anterieurs = [l for l in teintes.get(a.id, []) if l <= n.lineno]
                if anterieurs:
                    trouves.append((n.lineno, a.id, max(anterieurs)))
                elif a.id not in connus:
                    # L'AVEU. Regle de `gestion-ssh-key-5f` : un resolveur doit
                    # rendre « je n'ai pas resolu » plutot que rien. C'est le
                    # seul moyen qu'une forme de liaison a laquelle personne n'a
                    # pense se SIGNALE, au lieu de disparaitre en silence du
                    # cote qui dedouane. L'enumeration des formes n'a pas de fin.
                    non_resolus.append((n.lineno, a.id))
    return sorted(set(trouves)), sorted(set(non_resolus))


def _fichiers():
    """Les sources balayees, DERIVEES de l'arborescence et non listees."""
    out = []
    for dossier, sous, noms in os.walk(RACINE):
        sous[:] = [d for d in sous if d not in ('tests', '__pycache__', '_deprecated')]
        for nom in noms:
            if nom.endswith('.py'):
                out.append(os.path.join(dossier, nom))
    return sorted(out)


def releve(aveux=None):
    """{chemin relatif: [sites]} pour tout `backend/` hors `tests/`."""
    par_fichier = {}
    aveux = {} if aveux is None else aveux
    for chemin in _fichiers():
        with open(chemin, encoding='utf-8') as fh:
            source = fh.read()
        try:
            s, inconnus = sites_indirects(source)
        except SyntaxError:
            continue
        rel = os.path.relpath(chemin, RACINE)
        if s:
            par_fichier[rel] = s
        if inconnus:
            aveux[rel] = inconnus
    return par_fichier


# ══ LES TEMOINS ════════════════════════════════════════════════════════════════
# Chaque forme que l'instrument DOIT voir, et chaque forme qu'il ne doit PAS
# voir. Les neuf premieres etaient toutes invisibles a une version anterieure
# de ce balayage : elles sont ici parce qu'elles ont echoue, pas par symetrie.

_DOIT_MORDRE = [
    ('f-string affectee puis passee',
     "def f(c, p):\n    cmd = f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    ('ternaire, f-string dans la branche VRAIE',
     "def f(c, p):\n    cmd = f'rm {x}' if c else ''\n    execute_as_root(c, cmd, p)\n"),
    ('ternaire, f-string dans la branche FAUSSE',
     "def f(c, p):\n    cmd = '' if c else f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    ('concatenation avec une f-string',
     "def f(c, p):\n    cmd = 'a ' + f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    ('join sur une liste de f-strings',
     "def f(c, p):\n    cmd = ' && '.join([f'a{x}'])\n    execute_as_root(c, cmd, p)\n"),
    ('affectation augmentee',
     "def f(c, p):\n    cmd = 'a'\n    cmd += f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    ('walrus',
     "def f(c, p):\n    if (cmd := f'rm {x}'):\n        execute_as_root(c, cmd, p)\n"),
    ('cible en tuple',
     "def f(c, p):\n    a, cmd = 1, f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    ('affectation annotee',
     "def f(c, p):\n    cmd: str = f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    ('cible de boucle : for cmd in [f"a{x}"]',
     "def f(c, p):\n    for cmd in [f'a{x}', 'b']:\n        execute_as_root(c, cmd, p)\n"),
    ('boucle sur une variable teintee plus haut',
     "def f(c, p):\n    cmds = [f'a{x}']\n    for cmd in cmds:\n        execute_as_root(c, cmd, p)\n"),
    ('gestionnaire de contexte : with ... as cmd',
     "def f(c, p):\n    with ctx(f'a{x}') as cmd:\n        execute_as_root(c, cmd, p)\n"),
    ('comprehension',
     "def f(c, p):\n    [execute_as_root(c, cmd, p) for cmd in [f'a{x}']]\n"),
    ('alias : b = a, a teinte',
     "def f(c, p):\n    a = f'x{y}'\n    b = a\n    execute_as_root(c, b, p)\n"),
]

_NE_DOIT_PAS_MORDRE = [
    ('f-string EN LIGNE — semgrep la voit, la compter ici ferait un doublon',
     "def f(c, p):\n    execute_as_root(c, f'rm {x}', p)\n"),
    ('chaine litterale nue',
     "def f(c, p):\n    cmd = 'rm /tmp/x'\n    execute_as_root(c, cmd, p)\n"),
    ('f-string SANS interpolation',
     "def f(c, p):\n    cmd = f'rm /tmp'\n    execute_as_root(c, cmd, p)\n"),
    ('concatenation de deux litteraux',
     "def f(c, p):\n    cmd = 'a' + 'b'\n    execute_as_root(c, cmd, p)\n"),
    ('binding dans une AUTRE fonction',
     "def g():\n    cmd = f'{x}'\ndef f(c, p):\n    execute_as_root(c, cmd, p)\n"),
    ('binding APRES l appel',
     "def f(c, p):\n    execute_as_root(c, cmd, p)\n    cmd = f'{x}'\n"),
    ('appel a une autre fonction',
     "def f(c, p):\n    cmd = f'{x}'\n    subprocess.run(cmd)\n"),
    ('boucle sur des litteraux NUS',
     "def f(c, p):\n    for cmd in ['a', 'b']:\n        execute_as_root(c, cmd, p)\n"),
    ('variable NUE puis boucle',
     "def f(c, p):\n    cmds = ['a', 'b']\n    for cmd in cmds:\n        execute_as_root(c, cmd, p)\n"),
]


def test_les_formes_a_voir_sont_vues():
    """Neuf formes d'interpolation indirecte, toutes detectees."""
    for libelle, source in _DOIT_MORDRE:
        n = len(sites_indirects(source)[0])
        assert n == 1, f'forme NON DETECTEE ({libelle}) : {n} site(s) au lieu de 1'


def test_les_formes_a_ignorer_sont_ignorees():
    """Sept formes sûres ou deja couvertes, aucune signalee."""
    for libelle, source in _NE_DOIT_PAS_MORDRE:
        n = len(sites_indirects(source)[0])
        assert n == 0, f'FAUSSE ALARME ({libelle}) : {n} site(s) au lieu de 0'


def test_le_balayage_a_bien_lieu():
    """Un negatif exige un temoin : le balayage lit-il vraiment `backend/` ?

    Sans ceci, un compte de 0 serait indiscernable d'un balayage qui ne lit
    aucun fichier — et il se lirait comme une bonne nouvelle.
    """
    fichiers = _fichiers()
    assert len(fichiers) > 20, f'{len(fichiers)} fichiers balayes : le balayage ne lit rien'
    bases = {os.path.basename(f) for f in fichiers}
    assert 'sudo_manager.py' in bases, 'un ecrivain root connu manque au balayage'
    assert 'updates.py' in bases, 'le fichier de la vulnerabilite de 09-08 manque au balayage'
    assert not any(os.sep + 'tests' + os.sep in f for f in fichiers), \
        'le balayage lit ses propres fixtures'


def test_le_site_de_la_vulnerabilite_est_bien_dans_la_moitie_invisible():
    """`routes/updates.py` porte CINQ sites indirects, dont celui de la faille.

    Ce n'est pas un doublon du cliquet : c'est l'assertion qui donne un SENS a
    son zero. Si ce test tombait a zero pendant que le cliquet reste a zero, la
    conclusion « rien a signaler » serait fausse dans les deux moities.
    """
    par_fichier = releve()
    updates = par_fichier.get(os.path.join('routes', 'updates.py'), [])
    assert len(updates) == 5, f'{len(updates)} site(s) indirect(s) dans updates.py au lieu de 5'
    variables = {v for _, v, _ in updates}
    assert 'command' in variables, \
        'la variable de la vulnerabilite du 2026-09-08 a disparu du releve'


def test_l_instrument_AVOUE_ce_qu_il_ne_resout_pas():
    """Un resolveur doit rendre « je n'ai pas resolu » plutot que rien.

    Regle de `gestion-ssh-key-5f`, le 2026-09-09. Sa forme manquante — une cible
    de `for` — n'est ressortie que parce que SON releve imprimait « NON LIEE »
    au lieu de sauter en silence. Mon releve, lui, la perdait sans un mot : le
    compte tombait de 34 a 33, et un chiffre plus bas ressemble a un progres.

    > L'enumeration des formes de liaison n'a pas de fin. Ce qui a une fin, c'est
    > le silence : un nom non resolu doit se DIRE.

    Ce test verifie que le mecanisme existe et discrimine — pas que le depot
    contienne un cas particulier.
    """
    _, inconnus = sites_indirects(
        "def f(c, p):\n    execute_as_root(c, VENU_D_AILLEURS, p)\n"
    )
    assert inconnus, "un nom jamais lie dans la fonction doit etre AVOUE"
    _, connus = sites_indirects(
        "def f(c, p):\n    cmd = 'litteral'\n    execute_as_root(c, cmd, p)\n"
    )
    assert not connus, "un nom LIE, meme a un litteral, ne doit pas etre avoue"

    aveux = {}
    releve(aveux)
    for fichier, noms in aveux.items():
        for _, nom in noms:
            assert nom.isupper() or nom.startswith('_'), (
                f'{fichier} : `{nom}` non resolu et son nom ne dit pas une '
                f'constante de module — une forme de liaison echappe peut-etre'
            )


def test_le_cliquet_ne_monte_pas():
    """ECHOUE si le compte CROIT. Informe s'il descend — sans echouer.

    Une porte qui refuse toujours, on cesse de la regarder.
    """
    par_fichier = releve()
    total = sum(len(v) for v in par_fichier.values())
    if total > REFERENCE:
        detail = '\n'.join(
            f'    {f}:{l}  passe `{v}` (f-string posee a :{b})'
            for f, sites in sorted(par_fichier.items()) for l, v, b in sites
        )
        raise AssertionError(
            f'{total} commandes root indirectes contre {REFERENCE} en reference : '
            f'le compte a CRU de {total - REFERENCE}.\n'
            f'Une f-string affectee a une variable puis passee a `execute_as_root` '
            f'est INVISIBLE a la regle semgrep. Justifie le nouveau site, ou '
            f'retire-le.\n{detail}'
        )
    assert total >= 0
    if total < REFERENCE:
        print(f'\n[cliquet] {total} sites contre {REFERENCE} : descendre REFERENCE a {total}.')


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
    par_fichier = releve()
    total = sum(len(v) for v in par_fichier.values())
    print(f'\n  {total} commandes root indirectes (reference {REFERENCE})')
    for f, sites in sorted(par_fichier.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f'    {len(sites):3}  {f}')
