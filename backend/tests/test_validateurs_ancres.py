r"""
test_validateurs_ancres.py - AUCUN validateur ancre ne doit employer `.match()`.

┌─ LA CLASSE QUE CE TEST GARDE ────────────────────────────────────────────────┐
│ En python, `$` s'apparie AUSSI juste avant un saut de ligne terminal. Un      │
│ motif ancre aux deux bouts accepte donc `valeur\n` sous `.match()` — et cette │
│ valeur repart avec son `\n`, qui COUPE une commande shell en deux.            │
│                                                                               │
│ Confirme exploitable le 2026-09-08 sur `_SAFE_PKG` (`routes/updates.py`) :    │
│   POST /custom_update {"selected_packages": ["nginx\n", "reboot"]}            │
│     -> apt-get install -y nginx                                               │
│        [nouvelle ligne] reboot        <- execute en ROOT                       │
│                                                                               │
│ 58 appels ont ete convertis en `.fullmatch()`. Rien n'empechait la classe de   │
│ REVENIR : aucune regle semgrep ne la detecte, et le cliquet des trouvailles    │
│ ne la voit pas non plus.                                                      │
└──────────────────────────────────────────────────────────────────────────────┘

CE TEST EST DERIVE, PAS UNE LISTE. Il balaie `backend/` a chaque execution :
tout fichier NEUF est couvert sans qu'on y pense, et un fichier retire sort de
lui-meme. Il couvre les DEUX familles que mon premier releve avait manquees —
`re.match(r'^…$', X)` inline ET `MOTIF.match(X)` sur un motif compile, quel que
soit son nom (mon premier motif exigeait un underscore initial, et il a manque
9 sites sur 58).

⚠ CE QU'IL NE COUVRE PAS, et c'est ecrit plutot que suppose : un motif compile
dans un AUTRE fichier puis importe. `VALUE_RE` etait dans ce cas. Le balayage le
signale alors comme « motif introuvable » plutot que de le taire — un aveu, pas
un dedouanement.
"""

import os
import re

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ancre_a_la_fin(motif: str) -> bool:
    """Le motif finit-il par un `$` NON echappe et hors classe de caracteres ?"""
    if not motif.endswith('$'):
        return False
    # `\$` : compter les antislashs qui precedent
    i = len(motif) - 1
    antislashs = 0
    while i - 1 - antislashs >= 0 and motif[i - 1 - antislashs] == '\\':
        antislashs += 1
    if antislashs % 2 == 1:
        return False
    # `[...$]` non ferme : le `$` est alors litteral
    profondeur = 0
    k = 0
    while k < len(motif) - 1:
        c = motif[k]
        if c == '\\':
            k += 2
            continue
        if c == '[':
            profondeur += 1
        elif c == ']' and profondeur:
            profondeur -= 1
        k += 1
    return profondeur == 0


def _sources():
    for base, _, fichiers in os.walk(os.path.join(RACINE)):
        if os.sep + 'tests' in base or os.sep + '__pycache__' in base:
            continue
        for f in fichiers:
            if f.endswith('.py'):
                p = os.path.join(base, f)
                with open(p, encoding='utf-8', errors='replace') as fh:
                    yield os.path.relpath(p, RACINE), fh.read()


def _fautes(sources=None):
    """Rend [(fichier, ligne, quoi)] pour chaque validateur ancre en `.match()`.

    `sources` permet de LUI DONNER des sources forgees : sans ce parametre, le
    temoin ne pourrait verifier que les pieces de l'analyse, pas l'analyse.
    Un temoin qui verifie ce qu'on CLASSE ne verifie pas ce qu'on LIT.
    """
    fautes = []
    for chemin, src in (sources if sources is not None else _sources()):
        motifs = {}
        for m in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*re\.compile\(\s*(r?)(['\"])(.*?)\3",
            src, re.S,
        ):
            motifs[m.group(1)] = m.group(4)

        # famille A : `re.match(r'^…$', X)` inline
        for m in re.finditer(r"re\.match\(\s*(r?)(['\"])(.*?)\2", src, re.S):
            if _ancre_a_la_fin(m.group(3)):
                fautes.append((chemin, src[:m.start()].count('\n') + 1,
                               f"re.match inline sur {m.group(3)!r}"))

        # famille B : `MOTIF.match(X)` sur un motif compile ICI
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\.match\(", src):
            nom = m.group(1)
            if nom == 're':
                continue
            motif = motifs.get(nom)
            ligne = src[:m.start()].count('\n') + 1
            if motif is None:
                # aveu explicite : on ne peut pas trancher, on le DIT
                fautes.append((chemin, ligne,
                               f"{nom}.match() — motif introuvable dans ce fichier, "
                               "a verifier a la main"))
            elif _ancre_a_la_fin(motif):
                fautes.append((chemin, ligne, f"{nom}.match() sur {motif!r}"))
    return fautes


class TestAncrageDuValidateur:
    def test_aucun_validateur_ancre_n_emploie_match(self):
        fautes = _fautes()
        assert not fautes, (
            "un motif ancre par `$` employe avec `.match()` accepte un `\\n` "
            "FINAL, et ce saut de ligne coupe une commande shell en deux. "
            "Employer `.fullmatch()`.\n  "
            + "\n  ".join(f"{f}:{l}  {q}" for f, l, q in fautes)
        )


class TestLeBalayageMORD:
    """Le TEMOIN. Sans lui, un balayage casse rendrait la meme liste vide que
    l'absence de faute — et « zero » se lirait « propre »."""

    def test_l_analyseur_d_ancrage_discrimine(self):
        assert _ancre_a_la_fin(r'^[a-z]+$') is True
        assert _ancre_a_la_fin(r'^a[b$]+$') is True      # `$` dans une classe FERMEE
        assert _ancre_a_la_fin(r'^[a-z]+\$') is False    # `$` ECHAPPE
        assert _ancre_a_la_fin(r'^[a-z$]') is False      # ne finit pas par `$`
        assert _ancre_a_la_fin(r'\d{4}-\d{2}') is False  # prefixe delibere

    def test_le_balayage_lit_reellement_des_fichiers(self):
        """Si `_sources()` rendait vide, `_fautes()` rendrait vide aussi — et le
        test ci-dessus passerait sans rien mesurer."""
        noms = [c for c, _ in _sources()]
        assert len(noms) > 20, f"seulement {len(noms)} fichiers lus"
        assert any(c.endswith('sudo_manager.py') for c in noms), noms[:10]
        assert not any(os.sep + 'tests' in c for c in noms)

    def test_une_source_FORGEE_est_bien_accusee(self):
        """La contre-epreuve, BOUT EN BOUT : on donne au balayage une source
        fautive et il doit la rendre. Sans ce test, son zero sur l'arbre reel
        serait indiscernable d'un balayage casse."""
        fautive = (
            "import re\n"
            "_X = re.compile(r'^[a-z]+$')\n"
            "if _X.match(v):\n"
            "    pass\n"
        )
        trouve = _fautes([('forgee.py', fautive)])
        assert len(trouve) == 1, trouve
        assert trouve[0][1] == 3, trouve          # la ligne du `.match(`
        assert '_X.match()' in trouve[0][2], trouve

    def test_une_source_CORRECTE_n_est_pas_accusee(self):
        """L'autre bout : un `fullmatch` ne doit rien declencher, sinon la garde
        accuserait le code deja corrige — et on la desarmerait."""
        saine = (
            "import re\n"
            "_X = re.compile(r'^[a-z]+$')\n"
            "if _X.fullmatch(v):\n"
            "    pass\n"
        )
        assert _fautes([('saine.py', saine)]) == []

    def test_un_prefixe_DELIBERE_n_est_pas_accuse(self):
        """`monitoring.py` apparie un prefixe de date SANS `$` : c'est voulu, et
        la garde ne doit pas le convertir de force."""
        prefixe = (
            "import re\n"
            "if re.match(r'\\d{4}-\\d{2}-\\d{2}', ligne):\n"
            "    pass\n"
        )
        assert _fautes([('prefixe.py', prefixe)]) == []
