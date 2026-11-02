"""
`users.ssh_key` n'est plus lue par le backend — migration 067.

La colonne reste en base pour un retour arriere : un lecteur oublie
continuerait de deployer la cle UNIQUE d'avant, figee, pendant que les vraies
cles vivent dans `user_ssh_keys`. On demande au LANGAGE (tokenize) : seules les
CHAINES sont examinees — c'est la que vit le SQL —, jamais les commentaires.
"""
import io
import re
import tokenize
from pathlib import Path

RACINE = Path(__file__).resolve().parents[1]
# `ssh_key` comme MOT : pas `ssh_keys`, ni `ssh_key_manager`, ni `ssh_key_updated_at`.
MOT = re.compile(r'(?<![A-Za-z0-9_])ssh_key(?![A-Za-z0-9_])')


def _chaines_fautives(source):
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.STRING and MOT.search(tok.string) and re.search(r'(?i)\b(select|from|where|join)\b', tok.string):
            yield tok.start[0], tok.string[:80]


def test_aucune_requete_du_backend_ne_lit_l_ancienne_colonne():
    fichiers = [f for f in list(RACINE.glob('*.py')) + list((RACINE / 'routes').glob('*.py'))]
    assert len(fichiers) > 30, 'releve vide : la mesure n\'a pas eu lieu'
    fautes = [f"{f.name}:{ligne} {txt}" for f in fichiers
              for ligne, txt in _chaines_fautives(f.read_text(encoding='utf-8'))]
    assert fautes == [], fautes


def test_temoin_le_releve_reconnait_l_ancienne_requete():
    ancienne = 'cur.execute("SELECT COUNT(*) as cnt FROM users WHERE active = 1 AND ssh_key IS NOT NULL")\n'
    assert list(_chaines_fautives(ancienne)), 'le releve ne reconnait pas une lecture de la colonne'
