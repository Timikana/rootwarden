r"""
test_noms_qui_promettent_une_protection.py

┌─ LA CLASSE QUE CE TEST GARDE ────────────────────────────────────────────────┐
│ `re.escape` echappe pour une regex PYTHON. Mesure du 2026-09-09, python 3.13 │
│ — il laisse INTACTS :                                                        │
│                                                                              │
│     apostrophe · barre oblique · guillemet double · backtick                 │
│                                                                              │
│ et il echappe `$ & | ( . *`, l'espace et le saut de ligne. Les quatre qu'il   │
│ laisse passer sont exactement ceux qui comptent quand la valeur vit entre     │
│ APOSTROPHES de shell, ou dans une expression `s///`.                         │
│                                                                              │
│ Une variable nommee `escaped_key` a cet endroit-la AFFIRMAIT une protection   │
│ que la fonction ne fournit pas. Ce qui protegeait vraiment etait une liste    │
│ blanche AILLEURS — `_validate_directive` contre `ALLOWED_DIRECTIVES` dans un  │
│ fichier, `_SAFE_PARAM_RE` trente lignes plus haut dans l'autre.               │
│                                                                              │
│   > Un nom qui rassure a tort ne se contente pas de tromper son lecteur :     │
│   > il SE PROPAGE. Le prochain qui ecrira une commande a cote reutilisera la  │
│   > variable en la croyant sure.                                             │
└──────────────────────────────────────────────────────────────────────────────┘

Trouve SEPAREMENT par `gestion-ssh-key-c1` (`routes/supervision.py:368`) et par
moi (`ssh_audit.py:317` et `:411`). C'est le RECOUPEMENT qui l'a qualifie comme
classe, pas l'une ou l'autre mesure. `DOSSIER-62` §ⓐ.

CE QUE CE TEST NE FAIT PAS : il ne juge pas la SURETE des sites. Les trois sont
surs aujourd'hui, par leurs listes blanches respectives. Il garde le NOMMAGE,
parce que c'est le nom qui voyage.
"""

import ast
import os
import re

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Noms qui promettent un echappement. La liste est courte A DESSEIN : elle nomme
# ce qui a ete rencontre, pas ce qu'on imagine. Un nom qui apparaitrait demain
# sans etre ici passerait — et c'est pourquoi le test ci-dessous garde aussi le
# COMPTE des `re.escape`, qui lui est derive.
_NOMS_TROMPEURS = ('escaped_', '_escaped', 'shell_safe', 'safe_shell', 'quoted_key')

# Releve le 2026-09-09 : 3 appels a `re.escape` dans `backend/` hors tests.
REFERENCE_ESCAPES = 3


def _est_re_escape(fonc) -> bool:
    """`re.escape(...)` — et NON `html.escape(...)`, qui n'a rien a voir.

    ⚠ Mon premier predicat testait seulement `nom == 'escape'`. Il comptait donc
    les SEPT `_html.escape(...)` de `mail_utils.py`, qui echappent du HTML pour
    un courriel : 10 appels au lieu de 3. Le nom d'une methode ne dit pas de
    quel module elle vient — il faut lire le QUALIFICATEUR.

    Cette faute a ete attrapee parce qu'elle ALARMAIT (10 contre 3 en
    reference). Dans l'autre sens elle serait passee.
    """
    if not isinstance(fonc, ast.Attribute) or fonc.attr != 'escape':
        return False
    base = fonc.value
    return isinstance(base, ast.Name) and base.id == 're'


def _sources():
    out = []
    for dossier, sous, noms in os.walk(RACINE):
        sous[:] = [d for d in sous if d not in ('tests', '__pycache__', '_deprecated')]
        out += [os.path.join(dossier, n) for n in noms if n.endswith('.py')]
    return sorted(out)


def _appels_escape():
    """[(fichier, ligne, nom_de_la_cible_ou_None)] pour chaque `re.escape`."""
    trouves = []
    for chemin in _sources():
        with open(chemin, encoding='utf-8') as fh:
            source = fh.read()
        try:
            arbre = ast.parse(source)
        except SyntaxError:
            continue
        rel = os.path.relpath(chemin, RACINE)
        for n in ast.walk(arbre):
            if not isinstance(n, ast.Call):
                continue
            if not _est_re_escape(n.func):
                continue
            trouves.append((rel, n.lineno))
    return trouves


def _cibles_de_escape():
    """Les NOMS lies a un `re.escape(...)`, par fichier."""
    cibles = []
    for chemin in _sources():
        with open(chemin, encoding='utf-8') as fh:
            source = fh.read()
        try:
            arbre = ast.parse(source)
        except SyntaxError:
            continue
        rel = os.path.relpath(chemin, RACINE)
        for n in ast.walk(arbre):
            if not isinstance(n, ast.Assign) or not isinstance(n.value, ast.Call):
                continue
            if not _est_re_escape(n.value.func):
                continue
            for c in n.targets:
                if isinstance(c, ast.Name):
                    cibles.append((rel, n.lineno, c.id))
    return cibles


def test_le_balayage_a_bien_lieu():
    """Un negatif exige un temoin. Sans lui, « 0 nom trompeur » et « je n'ai
    rien lu » rendent la meme sortie."""
    fichiers = _sources()
    assert len(fichiers) > 20, f'{len(fichiers)} fichiers balayes'
    bases = {os.path.basename(f) for f in fichiers}
    assert 'ssh_audit.py' in bases and 'supervision.py' in bases
    appels = _appels_escape()
    assert appels, 're.escape introuvable : le balayage ne mesure rien'


def test_aucune_cible_de_re_escape_ne_promet_un_echappement_de_shell():
    """LE DEFAUT. Le nom doit dire ce que la valeur EST, pas ce qu'elle protege."""
    fautes = []
    for fichier, ligne, nom in _cibles_de_escape():
        for motif in _NOMS_TROMPEURS:
            if motif in nom:
                fautes.append(f'{fichier}:{ligne}  `{nom}` (motif « {motif} »)')
    assert not fautes, (
        're.escape echappe pour une regex PYTHON : il laisse intacts apostrophe, '
        'barre oblique, guillemet double et backtick. Un nom qui promet un '
        'echappement a cet endroit SE PROPAGE.\n  ' + '\n  '.join(fautes)
    )


def test_le_compte_des_re_escape_ne_monte_pas():
    """Chaque `re.escape` NEUF doit etre regarde : la classe est petite et
    fermee aujourd'hui. Le cliquet informe s'il descend, refuse s'il monte."""
    appels = _appels_escape()
    if len(appels) > REFERENCE_ESCAPES:
        detail = '\n  '.join(f'{f}:{l}' for f, l in appels)
        raise AssertionError(
            f'{len(appels)} appels a `re.escape` contre {REFERENCE_ESCAPES} en '
            f'reference. Chacun doit etre verifie : s\'il atterrit dans une '
            f'commande shell, ce n\'est PAS lui qui protege.\n  ' + detail
        )
    if len(appels) < REFERENCE_ESCAPES:
        print(f'\n[cliquet] {len(appels)} appels contre {REFERENCE_ESCAPES} : '
              f'descendre REFERENCE_ESCAPES.')


def test_les_trois_sites_nomment_leur_garde_REELLE():
    """Chaque site porte, en commentaire, le nom de ce qui le protege vraiment.

    Ce n'est pas de la documentation : c'est ce qui empeche le prochain lecteur
    de croire que `re.escape` suffit.
    """
    attendus = {
        os.path.join('ssh_audit.py'): 'ALLOWED_DIRECTIVES',
        os.path.join('routes', 'supervision.py'): '_SAFE_PARAM_RE',
    }
    for rel, garde in attendus.items():
        with open(os.path.join(RACINE, rel), encoding='utf-8') as fh:
            source = fh.read()
        commentaires = '\n'.join(
            l for l in source.split('\n') if l.strip().startswith('#'))
        assert 'REGEX PYTHON' in commentaires or 'regex PYTHON' in commentaires, \
            f'{rel} : aucun commentaire ne dit que re.escape echappe pour une regex Python'
        assert garde in commentaires, \
            f'{rel} : les commentaires ne nomment pas la garde reelle ({garde})'


def test_re_escape_laisse_bien_passer_les_quatre_caracteres():
    """La mesure sur laquelle tout repose, refaite a chaque execution.

    Si une version future de python echappait l'apostrophe, ce test tomberait —
    et ce serait une BONNE nouvelle a constater, pas un echec a ignorer.
    """
    intacts = ("'", '/', '"', '`')
    for c in intacts:
        assert re.escape(c) == c, (
            f're.escape({c!r}) rend {re.escape(c)!r} : python a change, '
            f'les commentaires de ce depot sont a remesurer'
        )
    for c in ('$', '&', '|', '(', '.', '*', ' ', '\n'):
        assert re.escape(c) != c, f're.escape n echappe plus {c!r}'


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
    print('\n  appels a re.escape :')
    for f, l in _appels_escape():
        print(f'    {f}:{l}')
    print('  cibles nommees :')
    for f, l, n in _cibles_de_escape():
        print(f'    {f}:{l}  {n}')
