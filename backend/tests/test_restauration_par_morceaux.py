"""
Relire une sauvegarde en memoire bornee — `_iter_sql`, 2026-10-26.

`verify_backup` et `restore_backup` lisaient le dump decompresse EN ENTIER puis
construisaient la liste de tous ses statements : une base dont la sauvegarde
vient enfin de tenir en memoire n'aurait pas pu etre relue. Le decoupage se fait
desormais morceau par morceau.

L'ORACLE est l'ancien `_split_sql`, recopie tel quel ci-dessous depuis la
version d'avant : le nouveau decoupage doit rendre EXACTEMENT la meme liste,
quel que soit l'endroit ou les morceaux sont coupes — y compris entre un
antislash et le caractere qu'il echappe.
"""
import gzip
import importlib
import random
import sys

import pytest


def _ancien_split_sql(text):
    """Decoupe un script SQL en statements en respectant les chaines simples
    quotees et l'echappement backslash (format produit par create_backup).
    Plus robuste qu'un split('; ') : un ';' dans une donnee ne casse rien."""
    stmts, buf, in_str, esc = [], [], False, False
    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == "'":
                in_str = False
        else:
            if ch == "'":
                in_str = True
                buf.append(ch)
            elif ch == ';':
                stmt = ''.join(buf).strip()
                if stmt:
                    stmts.append(stmt)
                buf = []
            else:
                buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        stmts.append(tail)
    # Retire les lignes de commentaire pures
    out = []
    for s in stmts:
        lines = [ln for ln in s.splitlines() if not ln.strip().startswith('--')]
        cleaned = '\n'.join(lines).strip()
        if cleaned:
            out.append(cleaned)
    return out


@pytest.fixture
def db_backup_reel(tmp_path, monkeypatch):
    saved = sys.modules.pop('db_backup', None)
    try:
        mod = importlib.import_module('db_backup')
        monkeypatch.setattr(mod, 'BACKUP_DIR', tmp_path)
        yield mod
    finally:
        sys.modules['db_backup'] = saved if saved is not None else mod


def _coupe(texte, rng):
    """Coupe `texte` en morceaux de tailles aleatoires (1 a 7 caracteres)."""
    morceaux, i = [], 0
    while i < len(texte):
        n = rng.randint(1, 7)
        morceaux.append(texte[i:i + n])
        i += n
    return morceaux


_CAS_ECRITS = [
    "INSERT INTO `t` VALUES ('a;b');\nINSERT INTO `t` VALUES ('c');",
    "INSERT INTO `t` VALUES ('l\\'apostrophe;');",
    "INSERT INTO `t` VALUES ('fin\\\\');INSERT INTO `t` VALUES ('x');",
    "-- RootWarden backup\n-- Database: x\n\nDROP TABLE IF EXISTS `t`;\nCREATE TABLE `t` (`id` int);\n",
    "SELECT 1;;  ;\n-- seul\n;SELECT 2",
    "INSERT INTO `t` VALUES ('ligne\n-- dans une chaine');",
    "",
]


@pytest.mark.parametrize('texte', _CAS_ECRITS)
def test_cas_ecrits_identiques_a_l_ancien_decoupage(db_backup_reel, texte):
    rng = random.Random(7)
    attendu = _ancien_split_sql(texte)
    assert db_backup_reel._split_sql(texte) == attendu
    for _ in range(50):
        assert list(db_backup_reel._iter_sql(_coupe(texte, rng))) == attendu


def test_textes_aleatoires_identiques_a_l_ancien_decoupage(db_backup_reel):
    rng = random.Random(20261026)
    alphabet = "ab';\\\n- "
    for _ in range(3000):
        texte = ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 60)))
        attendu = _ancien_split_sql(texte)
        coupe = _coupe(texte, rng)
        assert list(db_backup_reel._iter_sql(coupe)) == attendu, (texte, coupe)


def test_verify_backup_compte_sans_tout_lire(db_backup_reel, monkeypatch):
    dump = db_backup_reel.BACKUP_DIR / 'rootwarden_backup_20261026_020000.sql.gz'
    with gzip.open(dump, 'wt', encoding='utf-8') as f:
        f.write("-- RootWarden backup\n\nDROP TABLE IF EXISTS `t`;\nCREATE TABLE `t` (`id` int);\n\n")
        for i in range(5000):
            f.write(f"INSERT INTO `t` (`id`) VALUES ({i});\n")
    # Des morceaux minuscules : le resultat ne doit pas dependre de la coupe.
    lit = db_backup_reel._lit_par_morceaux
    monkeypatch.setattr(db_backup_reel, '_lit_par_morceaux', lambda p: lit(p, taille=13))

    r = db_backup_reel.verify_backup(dump.name)

    assert r['valid'] is True
    assert (r['tables'], r['statements']) == (1, 5002)
