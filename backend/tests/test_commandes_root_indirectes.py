r"""
test_commandes_root_indirectes.py - le RECENSEMENT des commandes root.

┌─ CE QUE CE FICHIER MESURE ───────────────────────────────────────────────────┐
│ TOUS les appels `execute_as_root*` de `backend/`, classes chacun dans         │
│ EXACTEMENT une categorie NOMMEE, avec un invariant :                          │
│                                                                               │
│     la somme des categories EGALE le nombre d'appels                          │
│                                                                               │
│ C'est cet invariant, et non la liste des categories, qui rend une omission    │
│ impossible a perdre. Un site d'une forme a laquelle personne n'a pense ne     │
│ disparait pas : il tombe dans une categorie d'AVEU et fait echouer son        │
│ cliquet.                                                                      │
└──────────────────────────────────────────────────────────────────────────────┘

═══ POURQUOI CE DESSIN, ET CE QU'IL REMPLACE ═══════════════════════════════════

La premiere version de ce fichier posait un aveu — « rendre *je n'ai pas resolu*
plutot que rien » — mais le posait EN AVAL de trois filtres silencieux :

    if not (n.func.id == 'execute_as_root'):        continue   <- 14 `_stream`
    if any(isinstance(a, JoinedStr) for a in args): continue   <- portee CALL
    if not isinstance(a, ast.Name):                 continue   <- 5 Subscript

    >>> L'AVEU N'AVOUAIT QUE CE QUE LES FILTRES AVAIENT LAISSE PASSER.

Signale par `gestion-ssh-key-5f` le 2026-09-09. Sa formule : *« ta regle est
bonne ; c'est sa POSITION qui la neutralise. »* Le remede n'etait pas d'ajouter
`Subscript` a la liste des formes — c'etait d'INVERSER L'ORDRE : compter d'abord
TOUS les appels root, ecarter ensuite avec une raison nommee, et faire porter
l'aveu sur ce qui a ete ecarte.

⚠ Le deuxieme filtre portait en plus sa faute au mauvais grain : il ecartait
l'appel ENTIER des qu'une f-string apparaissait dans N'IMPORTE QUEL argument.
Zero cas dans le depot aujourd'hui — c'est une forme, pas une trouvaille — mais
c'est le meme defaut de portee que le `pattern-not-regex` de semgrep : une
exemption scopee a la REGION au lieu de l'ARGUMENT.

═══ CE QUE CHAQUE CATEGORIE VEUT DIRE ══════════════════════════════════════════

  ① f-string EN LIGNE          vue par `rw-shell-fstring-execute-as-root`,
                               donc gardee par le cliquet semgrep (a ZERO).
  ② f-string sans interpolation  inerte : rien n'y entre.
  ③ litteral                   inerte.
  ④ INDIRECTE                  LE CHAMP DE CET INSTRUMENT : une f-string
                               interpolee, liee a un nom, puis passee.
                               INVISIBLE a la regle semgrep.
  ⑤ nom lie a une valeur non interpolee    resolu, et rien n'y entre.
  ⑥⑦⑧ AVEUX                    formes non resolues. Elles ne sont pas
                               declarees sures : elles sont declarees
                               NON CLASSEES, ce qui n'est pas la meme chose.

═══ TROIS RELEVES DE CETTE CLASSE SE SONT TROMPES, ET LE SENS COMPTE ═══════════

    fenetre de 3 lignes       20 / 18    ALARME     l'appel suivant credite
    portee MODULE             31 / 27    ALARME     binding 442 lignes plus loin
    isinstance(v, JoinedStr)  27 / 33    DEDOUANE   `f"{x}" if c else ""`
    cible de `for`            33 / 34    DEDOUANE   `for cmd in cmds`
    filtres en amont          34 / 37    DEDOUANE   `_stream`, `Subscript`
    portee non INTERNE        double     inflation  `ast.walk` descend dans les
                                                    fonctions imbriquees

Les quatre dernieres se ressemblent : **un chiffre plus bas ressemble a un
progres, et personne ne redemande la preuve d'une bonne nouvelle.** Aucune n'a
ete trouvee par relecture ; trois l'ont ete par un releve independant.

⚠ CE QUE CE FICHIER NE COUVRE PAS, ecrit plutot que suppose :
  · aucune analyse inter-procedurale : une commande qui traverse un appel
    intermediaire est classee sur ce qu'on voit ici ;
  · un appelee atteinte autrement que par son nom (`getattr`, un dict de
    fonctions) n'entre pas dans le recensement ;
  · le DOMAINE du gage n'est pas mesure — une valeur parfaitement neutralisee
    pour le shell peut etre dangereuse pour la grammaire du PUITS. Un
    `NOPASSWD` injecte dans `sudoers` par un heredoc irreprochable en est un
    cas reel (cf. la branche `security/runas-non-valide-sur-la-branche-custom`).
    Un cliquet a zero sur « la valeur est-elle injectable ? » ne dit RIEN de
    cette classe.
"""

import ast
import collections
import os

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── LES CLIQUETS ──────────────────────────────────────────────────────────────
# Releves le 2026-09-09 par ce meme recensement. Remesure :
#   python3 backend/tests/test_commandes_root_indirectes.py
REFERENCE_INDIRECTES = 37
REFERENCE_AVEUX = 10

CAT_EN_LIGNE = 'f-string EN LIGNE (vue par semgrep)'
CAT_INERTE_FSTRING = 'f-string sans interpolation'
CAT_LITTERAL = 'litteral'
CAT_INDIRECTE = 'INDIRECTE (invisible a semgrep)'
CAT_RESOLU_SUR = 'nom lie a une valeur non interpolee'
CAT_AVEU_ARITE = 'AVEU : moins de 2 arguments positionnels'
CAT_AVEU_NOM = 'AVEU : nom jamais lie dans la portee'
CAT_AVEU_FORME = 'AVEU : forme non resolue'

AVEUX = (CAT_AVEU_ARITE, CAT_AVEU_NOM, CAT_AVEU_FORME)


def _interpolee(noeud) -> bool:
    """Le sous-arbre contient-il une f-string INTERPOLEE, ou qu'elle soit ?

    Recursif A DESSEIN : tester `isinstance(valeur, JoinedStr)` manque le
    ternaire, la concatenation, le `.join`, l'affectation augmentee.
    """
    for n in ast.walk(noeud):
        if isinstance(n, ast.JoinedStr):
            if any(isinstance(v, ast.FormattedValue) for v in n.values):
                return True
    return False


def _nom_appelee(func):
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, 'id', None)


def recense(source: str):
    """Rend `Counter` des categories et `{categorie: [(appelee, ligne)]}`.

    L'invariant est verifie par `test_l_invariant_de_somme`.
    """
    arbre = ast.parse(source)

    # ── ① la portee la PLUS INTERNE de chaque noeud ──────────────────────────
    # `ast.walk(fonction)` descend dans les fonctions imbriquees : un appel place
    # dans une fonction interne serait compte une fois par portee englobante.
    # Mesure : 250 appels au lieu de 227 avant cette correction.
    interne = {}
    peres = {}

    def descend(noeud, portee):
        for fils in ast.iter_child_nodes(noeud):
            if isinstance(fils, (ast.FunctionDef, ast.AsyncFunctionDef)):
                peres[fils] = portee
                descend(fils, fils)
            else:
                interne[fils] = portee
                descend(fils, portee)

    descend(arbre, None)

    def teintures(fonction):
        """(noms teintes -> lignes, noms connus) pour une portee."""
        teintes = collections.defaultdict(list)
        connus = set()
        englobante = fonction
        while englobante is not None:
            connus |= {p.arg for p in ast.walk(englobante.args) if isinstance(p, ast.arg)}
            englobante = peres.get(englobante)
        corps = fonction if fonction is not None else arbre
        # DEUX passes : la seconde propage `for cmd in cmds` quand `cmds` n'est
        # teinte qu'apres la premiere.
        for _ in range(2):
            for n in ast.walk(corps):
                valeur = cibles = ligne = None
                if isinstance(n, ast.Assign):
                    valeur, cibles, ligne = n.value, n.targets, n.lineno
                elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
                    valeur, cibles, ligne = n.value, [n.target], n.lineno
                elif isinstance(n, (ast.For, ast.AsyncFor)):
                    # une cible de boucle n'est PAS un `ast.Assign`
                    valeur, cibles, ligne = n.iter, [n.target], n.lineno
                elif isinstance(n, ast.comprehension):
                    valeur, cibles, ligne = n.iter, [n.target], 0
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for item in n.items:
                        if item.optional_vars is None:
                            continue
                        for x in ast.walk(item.optional_vars):
                            if isinstance(x, ast.Name):
                                connus.add(x.id)
                                if _interpolee(item.context_expr):
                                    teintes[x.id].append(n.lineno)
                    continue
                if valeur is None:
                    continue
                teinte = _interpolee(valeur) or (
                    isinstance(valeur, ast.Name) and valeur.id in teintes)
                for cible in cibles:
                    for x in ast.walk(cible):
                        if isinstance(x, ast.Name):
                            connus.add(x.id)
                            if teinte and ligne not in teintes[x.id]:
                                teintes[x.id].append(ligne)
        return teintes, connus

    cache = {}
    comptes = collections.Counter()
    detail = collections.defaultdict(list)

    for n in ast.walk(arbre):
        if not isinstance(n, ast.Call):
            continue
        appelee = _nom_appelee(n.func)
        # `execute_as_root*` et non `== 'execute_as_root'` : les 14 appels
        # `execute_as_root_stream` executent des commandes root comme les autres,
        # et le filtre exact les ecartait de la population de tout le monde.
        if not (appelee and appelee.startswith('execute_as_root')):
            continue
        portee = interne.get(n)
        if portee not in cache:
            cache[portee] = teintures(portee)
        teintes, connus = cache[portee]

        if len(n.args) < 2:
            categorie = CAT_AVEU_ARITE
        else:
            commande = n.args[1]
            if isinstance(commande, ast.JoinedStr):
                categorie = CAT_EN_LIGNE if _interpolee(commande) else CAT_INERTE_FSTRING
            elif isinstance(commande, ast.Constant):
                categorie = CAT_LITTERAL
            elif isinstance(commande, ast.Name):
                if teintes.get(commande.id):
                    categorie = CAT_INDIRECTE
                elif commande.id in connus:
                    categorie = CAT_RESOLU_SUR
                else:
                    categorie = CAT_AVEU_NOM
            else:
                categorie = CAT_AVEU_FORME
        comptes[categorie] += 1
        detail[categorie].append((appelee, n.lineno))
    return comptes, detail


def _fichiers():
    """Les sources balayees, DERIVEES de l'arborescence et non listees."""
    out = []
    for dossier, sous, noms in os.walk(RACINE):
        sous[:] = [d for d in sous if d not in ('tests', '__pycache__', '_deprecated')]
        out += [os.path.join(dossier, n) for n in noms if n.endswith('.py')]
    return sorted(out)


def releve():
    """(comptes globaux, {fichier: {categorie: [(appelee, ligne)]}})."""
    globaux = collections.Counter()
    par_fichier = {}
    for chemin in _fichiers():
        with open(chemin, encoding='utf-8') as fh:
            source = fh.read()
        try:
            comptes, detail = recense(source)
        except SyntaxError:
            continue
        if comptes:
            globaux += comptes
            par_fichier[os.path.relpath(chemin, RACINE)] = detail
    return globaux, par_fichier


# ══ LES TEMOINS ════════════════════════════════════════════════════════════════
# Chacun classe UN appel dans UNE categorie attendue. Les formes marquees ⟵ ont
# ete ajoutees apres avoir ete MANQUEES : elles sont ici parce qu'elles ont
# echoue, pas par symetrie.

_TEMOINS = [
    (CAT_INDIRECTE, 'f-string affectee puis passee',
     "def f(c, p):\n    cmd = f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'ternaire, branche VRAIE',                                   # ⟵ IfExp
     "def f(c, p):\n    cmd = f'rm {x}' if c else ''\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'ternaire, branche FAUSSE',                                  # ⟵ IfExp
     "def f(c, p):\n    cmd = '' if c else f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'concatenation',
     "def f(c, p):\n    cmd = 'a ' + f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'join sur une liste de f-strings',
     "def f(c, p):\n    cmd = ' && '.join([f'a{x}'])\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'affectation augmentee',
     "def f(c, p):\n    cmd = 'a'\n    cmd += f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'walrus',
     "def f(c, p):\n    if (cmd := f'rm {x}'):\n        execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'cible en tuple',
     "def f(c, p):\n    a, cmd = 1, f'{x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'affectation annotee',
     "def f(c, p):\n    cmd: str = f'rm {x}'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'cible de boucle',                                           # ⟵ For
     "def f(c, p):\n    for cmd in [f'a{x}']:\n        execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'boucle sur une variable teintee',                           # ⟵ For
     "def f(c, p):\n    cmds = [f'a{x}']\n    for cmd in cmds:\n        execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'gestionnaire de contexte',
     "def f(c, p):\n    with ctx(f'a{x}') as cmd:\n        execute_as_root(c, cmd, p)\n"),
    (CAT_INDIRECTE, 'comprehension',
     "def f(c, p):\n    [execute_as_root(c, cmd, p) for cmd in [f'a{x}']]\n"),
    (CAT_INDIRECTE, 'alias b = a',
     "def f(c, p):\n    a = f'x{y}'\n    b = a\n    execute_as_root(c, b, p)\n"),
    (CAT_INDIRECTE, 'la variante _stream compte comme les autres',               # ⟵ filtre exact
     "def f(c, p):\n    cmd = f'rm {x}'\n    execute_as_root_stream(c, cmd, p)\n"),
    (CAT_EN_LIGNE, 'f-string en ligne',
     "def f(c, p):\n    execute_as_root(c, f'rm {x}', p)\n"),
    (CAT_LITTERAL, 'chaine litterale',
     "def f(c, p):\n    execute_as_root(c, 'rm /tmp/x', p)\n"),
    (CAT_INERTE_FSTRING, 'f-string sans interpolation',
     "def f(c, p):\n    execute_as_root(c, f'rm /tmp', p)\n"),
    (CAT_RESOLU_SUR, 'nom lie a un litteral',
     "def f(c, p):\n    cmd = 'rm /tmp/x'\n    execute_as_root(c, cmd, p)\n"),
    (CAT_RESOLU_SUR, 'boucle sur des litteraux nus',
     "def f(c, p):\n    for cmd in ['a', 'b']:\n        execute_as_root(c, cmd, p)\n"),
    (CAT_AVEU_NOM, 'nom jamais lie dans la portee',
     "def f(c, p):\n    execute_as_root(c, VENU_D_AILLEURS, p)\n"),
    (CAT_AVEU_FORME, 'indice de dictionnaire',                                   # ⟵ Subscript
     "def f(c, p):\n    execute_as_root(c, REGISTRE['cmd'], p)\n"),
    (CAT_AVEU_FORME, 'attribut',
     "def f(c, p):\n    execute_as_root(c, self.cmd, p)\n"),
    (CAT_AVEU_FORME, 'appel intermediaire',
     "def f(c, p):\n    execute_as_root(c, fabrique(x), p)\n"),
    (CAT_AVEU_ARITE, 'appel a un seul argument',
     "def f(c, p):\n    execute_as_root(c)\n"),
]


def test_chaque_temoin_tombe_dans_SA_categorie():
    """25 formes, 25 categories attendues — dont 5 ajoutees apres un manque."""
    for attendue, libelle, source in _TEMOINS:
        comptes, _ = recense(source)
        assert sum(comptes.values()) == 1, \
            f'{libelle} : {sum(comptes.values())} appel(s) recense(s) au lieu de 1'
        obtenue = next(iter(comptes))
        assert obtenue == attendue, \
            f'{libelle} : classe « {obtenue} » au lieu de « {attendue} »'


def test_l_invariant_de_somme():
    """La somme des categories EGALE le nombre d'appels root du depot.

    C'est l'invariant qui rend une omission impossible a perdre : il n'y a pas
    de sortie silencieuse, seulement des categories — dont trois sont des aveux.
    """
    total_par_categorie = 0
    total_appels = 0
    for chemin in _fichiers():
        with open(chemin, encoding='utf-8') as fh:
            source = fh.read()
        try:
            arbre = ast.parse(source)
        except SyntaxError:
            continue
        # comptage INDEPENDANT, sans passer par `recense` : si les deux comptes
        # venaient du meme balayage, l'invariant serait une tautologie.
        total_appels += sum(
            1 for n in ast.walk(arbre)
            if isinstance(n, ast.Call)
            and (_nom_appelee(n.func) or '').startswith('execute_as_root')
        )
        comptes, _ = recense(source)
        total_par_categorie += sum(comptes.values())
    assert total_appels > 100, f'{total_appels} appels : le balayage ne lit rien'
    assert total_par_categorie == total_appels, (
        f'{total_par_categorie} classes contre {total_appels} appels : '
        f'{total_appels - total_par_categorie} site(s) sortent SANS CATEGORIE'
    )


def test_le_balayage_a_bien_lieu():
    """Un negatif exige un temoin : le balayage lit-il vraiment `backend/` ?"""
    fichiers = _fichiers()
    assert len(fichiers) > 20, f'{len(fichiers)} fichiers balayes'
    bases = {os.path.basename(f) for f in fichiers}
    assert 'sudo_manager.py' in bases and 'updates.py' in bases
    assert not any(os.sep + 'tests' + os.sep in f for f in fichiers), \
        'le balayage lit ses propres fixtures'


def test_le_site_de_la_vulnerabilite_est_dans_la_moitie_invisible():
    """`routes/updates.py` porte des sites INDIRECTS, dont celui de la faille.

    Ce n'est pas un doublon du cliquet semgrep : c'est l'assertion qui donne un
    SENS a son zero. Si elle tombait pendant que le cliquet reste a zero, « rien
    a signaler » serait faux des deux cotes.
    """
    _, par_fichier = releve()
    updates = par_fichier.get(os.path.join('routes', 'updates.py'), {})
    indirectes = updates.get(CAT_INDIRECTE, [])
    assert len(indirectes) >= 5, \
        f'{len(indirectes)} site(s) indirect(s) dans updates.py, au moins 5 attendus'


def test_le_cliquet_des_indirectes_ne_monte_pas():
    """ECHOUE si le compte CROIT. Informe s'il descend, sans echouer."""
    globaux, par_fichier = releve()
    total = globaux[CAT_INDIRECTE]
    if total > REFERENCE_INDIRECTES:
        detail = '\n'.join(
            f'    {f}:{l}  {appelee}'
            for f, cats in sorted(par_fichier.items())
            for appelee, l in cats.get(CAT_INDIRECTE, [])
        )
        raise AssertionError(
            f'{total} commandes root INDIRECTES contre {REFERENCE_INDIRECTES} : '
            f'le compte a CRU de {total - REFERENCE_INDIRECTES}. Une f-string liee '
            f'a un nom puis passee a `execute_as_root` est INVISIBLE a la regle '
            f'semgrep.\n{detail}'
        )
    if total < REFERENCE_INDIRECTES:
        print(f'\n[cliquet] {total} indirectes contre {REFERENCE_INDIRECTES} : '
              f'descendre REFERENCE_INDIRECTES a {total}.')


def test_le_cliquet_des_AVEUX_ne_monte_pas():
    """Le cliquet le plus important : il garde ce que l'instrument NE SAIT PAS.

    Un aveu qui augmente veut dire qu'une forme nouvelle est apparue et que
    personne ne l'a classee. C'est le seul endroit ou « je ne sais pas » a un
    compte, donc le seul ou l'ignorance ne peut pas se dissoudre en silence.
    """
    globaux, par_fichier = releve()
    total = sum(globaux[c] for c in AVEUX)
    if total > REFERENCE_AVEUX:
        detail = '\n'.join(
            f'    {f}:{l}  {appelee}  [{c}]'
            for f, cats in sorted(par_fichier.items())
            for c in AVEUX for appelee, l in cats.get(c, [])
        )
        raise AssertionError(
            f'{total} appels root NON CLASSES contre {REFERENCE_AVEUX} en '
            f'reference. Ils ne sont pas declares dangereux : ils sont declares '
            f'NON RESOLUS, ce qui n est pas la meme chose.\n{detail}'
        )
    if total < REFERENCE_AVEUX:
        print(f'\n[cliquet] {total} aveux contre {REFERENCE_AVEUX} : '
              f'descendre REFERENCE_AVEUX a {total}.')


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
    globaux, par_fichier = releve()
    total = sum(globaux.values())
    print(f'\n  {total} appels `execute_as_root*` dans backend/ hors tests')
    for cat, n in globaux.most_common():
        marque = '  ⚠' if cat in AVEUX else '   '
        print(f'   {marque} {n:4}  {cat}')
    print(f'\n  INDIRECTES : {globaux[CAT_INDIRECTE]} (reference {REFERENCE_INDIRECTES})')
    print(f'  AVEUX      : {sum(globaux[c] for c in AVEUX)} (reference {REFERENCE_AVEUX})')
