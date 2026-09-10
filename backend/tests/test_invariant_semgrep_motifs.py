"""
test_invariant_semgrep_motifs.py — LES MOTIFS DE NOS REGLES DOIVENT COMPILER.

    Un motif semgrep pour Python doit etre du Python valide. Un motif qui ne
    compile pas ne cherche RIEN : la regle est morte, en silence cote depot, et
    l'erreur ne vit que dans le journal d'un job `continue-on-error`.

POURQUOI CE FICHIER EXISTE
--------------------------
Trois des dix regles de `.semgrep/rules-rootwarden.yml` n'ont **jamais** compile
depuis leur ecriture (2026-05-19). Mesure : les blocs sont identiques a l'octet
depuis `cc0220e`, et le job `sast-semgrep-custom` n'a **jamais** ete vert —
19 executions depuis sa premiere apparition, 13 `failure`, 1 `cancelled`,
5 absentes, **0 `success`**.

La convention `CONTRIBUTING-SECURITY.md` annoncait donc trois protections qui
n'ont jamais existe : une f-string shell executee en root, un `echo` PHP non
echappe, une route Flask sans cle d'API.

**Rien dans le depot ne le disait.** Le seul signal etait un rouge tolere, et un
rouge tolere devient une propriete du decor.

CE QUE CE TEST MESURE, ET CE QU'IL NE MESURE PAS
------------------------------------------------
Il mesure une condition **NECESSAIRE** : le motif est du Python valide. Semgrep
ajoute sa propre grammaire par-dessus, donc passer ici ne garantit pas que
semgrep accepte le motif — **et surtout pas qu'il MORDE**. Une regle qui compile
et ne matche jamais est indiscernable d'une regle qui compile et n'a rien a
matcher ; seul un fichier d'epreuve par regle trancherait cela.

Ce test ne remplace donc pas le job CI : il rend son echec REPRODUCTIBLE
localement, sans installer semgrep — qui n'est disponible ni sur l'hote ni dans
aucun conteneur de ce depot.

LES TROIS SUBSTITUTIONS, ET POURQUOI CHACUNE
--------------------------------------------
Chacune vient d'une mesure, pas d'une supposition :

  1. `...` SEUL sur sa ligne  ->  `pass`. C'est une ellipse d'instruction.
  2. `...` en position d'ARGUMENT  ->  RETIRE. Le remplacer par un identifiant
     fabriquait un « positional argument follows keyword argument » sur
     `subprocess.run(..., shell=True, ...)`, qui est du semgrep parfaitement
     valide. **Premiere version de ce test : elle accusait cette regle a tort.**
     Le journal CI ne rapporte que TROIS erreurs ; c'est lui qui a servi de
     verite terrain contre mon propre instrument.
  3. `$VAR`  ->  identifiant, **mais JAMAIS a l'interieur d'une f-string** :
     c'est precisement la que semgrep ne substitue pas non plus, et donc la que
     le motif doit etre valide TEL QUEL. Substituer partout masquait le defaut
     de `rw-shell-fstring-execute-as-root` — **le harnais rendait alors un faux
     PASS sur le defaut qu'il existe pour trouver.**
"""
import ast
import json
import pathlib
import re
import subprocess
import sys

import pytest

REGLES = pathlib.Path(__file__).resolve().parent.parent.parent / '.semgrep' / 'rules-rootwarden.yml'


def _valide_python(motif: str):
    """Le motif est-il du Python valide ? Rend (ok, message)."""
    s = re.sub(r'(?m)^(\s*)\.\.\.\s*$', r'\1pass', motif)
    s = re.sub(r'\.\.\.\s*,\s*', '', s)
    s = re.sub(r',\s*\.\.\.', '', s)
    s = re.sub(r'\(\s*\.\.\.\s*\)', '()', s)
    # metavariables HORS f-string uniquement (substitution 3 du docstring)
    morceaux, i = [], 0
    for f in re.finditer(r'f["\'](?:[^"\'\\]|\\.)*["\']', s):
        morceaux.append(re.sub(r'\$[A-Z_][A-Z0-9_]*', '_MV', s[i:f.start()]))
        morceaux.append(f.group(0))
        i = f.end()
    morceaux.append(re.sub(r'\$[A-Z_][A-Z0-9_]*', '_MV', s[i:]))
    try:
        ast.parse(''.join(morceaux))
        return True, ''
    except SyntaxError as e:
        return False, f'{e.msg} (ligne {e.lineno})'


def _motifs(regle):
    """Tous les motifs textuels d'une regle, `*-regex` exclus."""
    trouves = []

    def creuse(o):
        if isinstance(o, dict):
            for cle, val in o.items():
                if cle.startswith('pattern') and not cle.endswith('regex') and isinstance(val, str):
                    trouves.append((cle, val))
                else:
                    creuse(val)
        elif isinstance(o, list):
            for x in o:
                creuse(x)

    creuse(regle)
    return trouves


@pytest.fixture(scope='module')
def regles():
    if not REGLES.is_file():
        pytest.fail(f'fichier de regles introuvable : {REGLES}')
    try:
        import yaml
    except ImportError:
        pytest.skip('pyyaml absent — ce test exige le lecteur YAML')
    d = yaml.safe_load(REGLES.read_text(encoding='utf-8'))
    return d['rules']


def test_l_analyse_a_bien_lu_le_fichier(regles):
    """L'INSTRUMENT D'ABORD. Un fichier vide rend toute propriete vraie."""
    assert len(regles) >= 10, f'{len(regles)} regles lues — analyse creuse'
    py = [r for r in regles if 'python' in r.get('languages', [])]
    assert len(py) >= 4, f'{len(py)} regles Python — le champ `languages` a change ?'
    assert sum(len(_motifs(r)) for r in py) >= 4, 'aucun motif extrait — la structure a change'


def test_le_harnais_rejette_bien_un_motif_FAUTIF():
    """LE TEMOIN. Sans lui, « aucun rejet » et « le harnais ne regarde plus »
    sont la MEME sortie. Les trois temoins sont les trois motifs reellement
    trouves morts le 2026-09-03."""
    for fautif in (
        'execute_as_root($CLIENT, f"...{$VAR}...", ...)',
        'execute_as_root($CLIENT, f"...{base64...}...", ...)',
        '@bp.route(...)\n@require_api_key\n...\ndef $F(...):\n  ...',
    ):
        ok, _ = _valide_python(fautif)
        assert not ok, f'le harnais ACCEPTE un motif connu fautif :\n{fautif}'


def test_le_harnais_accepte_un_motif_semgrep_IDIOMATIQUE():
    """LA CONTRE-EPREUVE. Un harnais qui rejette tout ne mesure rien. Ces
    formes sont du semgrep valide et DOIVENT passer — la deuxieme est celle sur
    laquelle la premiere version de ce test accusait a tort."""
    for bon in (
        'execute_as_root($CLIENT, $CMD, ...)',
        'subprocess.run(..., shell=True, ...)',
        '@bp.route(...)\ndef $F(...):\n  ...',
    ):
        ok, err = _valide_python(bon)
        assert ok, f'le harnais REJETTE un motif idiomatique :\n{bon}\n-> {err}'


def test_tous_les_motifs_python_compilent(regles):
    """L'INVARIANT. Un motif qui ne compile pas ne cherche rien."""
    casses = []
    for r in regles:
        if 'python' not in r.get('languages', []):
            continue
        for cle, motif in _motifs(r):
            ok, err = _valide_python(motif)
            if not ok:
                casses.append(f"{r['id']} / {cle} : {err}\n      {motif.strip().splitlines()[0][:78]}")
    assert not casses, (
        'Motifs Python qui ne compilent pas — ces regles ne cherchent RIEN :\n  '
        + '\n  '.join(casses)
        + '\n\nUn motif semgrep doit etre du Python valide. Rappel : semgrep ne '
          'substitue PAS de metavariable a l interieur d une f-string.')
