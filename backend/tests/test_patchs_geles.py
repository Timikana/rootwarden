"""
test_patchs_geles.py - un patch gele appelle-t-il un nom de journal qui
n'existe pas dans sa cible ?

LE DEFAUT MESURE. Un patch en attente ecrivait `logger.error(...)` dans
`backend/scheduler.py`, qui definit `_log` et n'a **aucun** `logger`. Applique,
il aurait leve `NameError` — dans la branche de REFUS, c'est-a-dire au moment
exact ou elle sert.

    git apply --check   PASSE   il verifie que le diff s'applique
    ast.parse           PASSE   la syntaxe est correcte
    import du module    PASSE   le nom n'est resolu qu'a l'EXECUTION
    -> AUCUN des trois n'execute la branche

LE DISCRIMINANT : le nom de journal appele par les lignes AJOUTEES a-t-il
d'autres usages dans le fichier CIBLE ?

    01-E-231      supervision.py  `logger.`   33 autres   sain
    04-E-281      scheduler.py    `_log.`     42 autres   sain
    QUARANTAINE   scheduler.py    `logger.`    0 autre     LA FAUTE

┌─ ⚠ LA LATENCE, ET ELLE N'EST PAS UN TROU MAIS ELLE SE DIT ─────────────────┐
│ La CI ne joue que sur `main` (`on: push branches:[main]`). Les patchs se     │
│ modifient sur `Migration-Laravel`. **Un patch defectueux peut donc dormir   │
│ jusqu'a la fusion suivante.** Ce fichier n'est pas un garde continu : c'est  │
│ un garde de FUSION. Lire « la CI le garde » comme « il est garde en          │
│ continu » serait faux.                                                       │
└─────────────────────────────────────────────────────────────────────────────┘

┌─ OU CE FICHIER MESURE, ET OU IL S'ABSTIENT ────────────────────────────────┐
│ `docs/` n'est monte dans AUCUN conteneur : `rootwarden_python` ne voit que   │
│ `backend/ -> /app`. Joue dans le conteneur, ce fichier NE PEUT PAS lire les  │
│ patchs, et il le DIT — `skip` avec sa raison nommee.                        │
│                                                                              │
│ En CI, `test-python` tourne sur un checkout complet (`working-directory:     │
│ backend`), donc les patchs sont visibles en `../docs/`. La ou ce fichier est │
│ le gardien, il ECHOUE FERME : si `GITHUB_ACTIONS` est defini et que le       │
│ dossier manque, c'est un FAIL et non un skip.                               │
│                                                                              │
│ *Un skip aveugle est un garde sans objet ; un skip qui nomme sa fenetre n'en │
│ est pas un.*                                                                 │
└─────────────────────────────────────────────────────────────────────────────┘
"""
import os
import pathlib
import re
import shutil
import subprocess

import pytest


APPELS_DE_JOURNAL = re.compile(
    r'\b(?P<nom>[A-Za-z_][A-Za-z0-9_]*)\.(?:error|warning|warn|info|debug|exception|critical)\s*\(')

QUARANTAINE = 'QUARANTAINE'


def _dossier_des_patchs():
    """Le dossier des patchs, ou `None` s'il n'est pas visible d'ici."""
    for parent in pathlib.Path(__file__).resolve().parents:
        candidat = parent / 'docs' / 'migration' / 'patchs-en-attente'
        if candidat.is_dir():
            return candidat
    return None


def _racine_du_depot(dossier):
    return dossier.parents[2]


@pytest.fixture(scope='module')
def patchs():
    dossier = _dossier_des_patchs()
    if dossier is None:
        if os.environ.get('GITHUB_ACTIONS'):
            pytest.fail(
                "`docs/migration/patchs-en-attente/` est INTROUVABLE alors que "
                "GITHUB_ACTIONS est defini : c'est ici que ce garde mord, et il "
                "n'a rien pu mesurer. Verifier le checkout et le repertoire de "
                'travail du job.')
        pytest.skip(
            "SANS OBJET ICI : `docs/` n'est monte dans aucun conteneur — "
            "`rootwarden_python` ne voit que `backend/ -> /app`. Ce garde mord "
            'en CI, sur un checkout complet. Ce skip nomme sa fenetre : il ne '
            "vaut PAS « rien a signaler ».")
    trouves = sorted(dossier.glob('*.patch'))
    assert trouves, f"aucun patch dans {dossier} : mesure invalide"
    return trouves


def _cible(patch: pathlib.Path):
    """Le fichier vise par le patch, tel que son en-tete le declare."""
    for ligne in patch.read_text(encoding='utf-8', errors='replace').splitlines():
        if ligne.startswith('+++ '):
            chemin = ligne[4:].strip()
            return chemin[2:] if chemin.startswith('b/') else chemin
    return None


def _noms_de_journal_ajoutes(patch: pathlib.Path):
    """Les noms de journal appeles par les lignes AJOUTEES du patch.

    On ne lit que les `+` : ce qui existait deja dans la cible n'est pas la
    question. Et on exclut les lignes de commentaire ajoutees — un exemple dans
    un commentaire n'est pas un appel.
    """
    noms = set()
    for ligne in patch.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ligne.startswith('+') or ligne.startswith('+++'):
            continue
        contenu = ligne[1:]
        if contenu.lstrip().startswith('#'):
            continue
        for m in APPELS_DE_JOURNAL.finditer(contenu):
            noms.add(m.group('nom'))
    return noms


def _autres_usages(racine, chemin_cible, nom):
    """Combien de fois `<nom>.` apparait dans la cible, hors commentaires."""
    fichier = racine / chemin_cible
    if not fichier.is_file():
        return None
    total = 0
    for ligne in fichier.read_text(encoding='utf-8', errors='replace').splitlines():
        if ligne.lstrip().startswith('#'):
            continue
        total += len(re.findall(rf'\b{re.escape(nom)}\s*\.', ligne))
    return total


# ══════════════════════════════════════════════════════════════════════════════
# LE TEMOIN, EN PREMIER — s'il ne mord pas, l'instrument est mort
# ══════════════════════════════════════════════════════════════════════════════

def test_TEMOIN_le_discriminant_RETROUVE_le_patch_en_quarantaine(patchs):
    """LE PATCH EN QUARANTAINE PORTE LA FAUTE, ET LE DISCRIMINANT DOIT LA VOIR.

    C'est ce qui valide l'instrument. **S'il ne la retrouve pas, ce ne sont pas
    les patchs qui sont sains : c'est la sonde qui est morte** — et les tests
    suivants passeraient alors tous, en ne mesurant rien.

    Le patch est deja ecarte ; on ne le mesure pas pour le corriger, on le
    mesure pour eprouver la regle.
    """
    quarantaine = [p for p in patchs if QUARANTAINE in p.name]
    assert quarantaine, (
        'aucun patch en quarantaine : le temoin de cet instrument a disparu. '
        "Sans lui, les tests suivants passent sans qu'on sache s'ils voient "
        'quoi que ce soit.')

    racine = _racine_du_depot(_dossier_des_patchs())
    fautifs = []
    for patch in quarantaine:
        cible = _cible(patch)
        for nom in _noms_de_journal_ajoutes(patch):
            autres = _autres_usages(racine, cible, nom)
            if autres == 0:
                fautifs.append((patch.name, cible, nom))

    assert fautifs, (
        "LE DISCRIMINANT NE RETROUVE PLUS LA FAUTE CONNUE. L'instrument est "
        'mort, pas les patchs sains. Ne pas conclure des tests suivants avant '
        "d'avoir repare celui-ci.")


# ══════════════════════════════════════════════════════════════════════════════
# LA MESURE — sur les patchs qui, eux, sont destines a etre appliques
# ══════════════════════════════════════════════════════════════════════════════

def test_aucun_patch_actif_n_appelle_un_journal_absent_de_sa_cible(patchs):
    """La faute du patch en quarantaine ne doit pas exister dans les autres.

    `git apply --check`, `ast.parse` et l'import du module la laissent TOUS LES
    TROIS passer : un nom global n'est resolu qu'a l'execution, et aucun des
    trois n'execute la branche ou il vit.
    """
    racine = _racine_du_depot(_dossier_des_patchs())
    fautes = []
    for patch in patchs:
        if QUARANTAINE in patch.name:
            continue
        cible = _cible(patch)
        assert cible is not None, f"{patch.name} n'a pas d'en-tete `+++`"
        for nom in _noms_de_journal_ajoutes(patch):
            autres = _autres_usages(racine, cible, nom)
            assert autres is not None, (
                f"{patch.name} vise `{cible}`, qui est introuvable : le patch "
                'ou son en-tete est perime')
            if autres == 0:
                fautes.append(f"{patch.name} appelle `{nom}.` dans `{cible}`, "
                              f'qui ne le definit ni ne l\'emploie ailleurs')

    assert not fautes, (
        'un patch gele appelle un nom de journal absent de sa cible — meme '
        'faute que le patch en quarantaine, et elle leve un `NameError` DANS '
        'LA BRANCHE DE REFUS, au moment exact ou elle sert :\n  - '
        + '\n  - '.join(fautes))


def test_chaque_patch_declare_une_cible_qui_existe(patchs):
    """Un patch dont la cible a disparu ou change de nom est PERIME, et un patch
    perime qu'on croit prêt est le meme danger qu'un patch fautif."""
    racine = _racine_du_depot(_dossier_des_patchs())
    absents = []
    for patch in patchs:
        cible = _cible(patch)
        if cible is None or not (racine / cible).is_file():
            absents.append(f'{patch.name} -> {cible!r}')

    assert not absents, ('patch(s) dont la cible declaree n\'existe pas : \n  - '
                         + '\n  - '.join(absents))


# ══════════════════════════════════════════════════════════════════════════════
# F821 — plus fort que le discriminant, quand l'outillage est la
# ══════════════════════════════════════════════════════════════════════════════

def test_ruff_F821_sur_les_patchs_appliques(patchs, tmp_path):
    """`ruff --select F821` voit TOUT nom non defini, pas seulement un journal.

    Le discriminant ci-dessus ne connait qu'une famille de fautes — celle qu'on
    a rencontree. F821 ne suppose rien de la forme du nom, donc il attrape la
    prochaine, qui ne ressemblera pas a la precedente.

    Il exige `git` ET `ruff`. Quand l'un manque, ce test s'ABSTIENT EN LE DISANT
    plutot que de passer : le discriminant reste alors le seul filet, et il faut
    savoir qu'on est dans ce cas.
    """
    if not shutil.which('git') or not shutil.which('ruff'):
        pytest.skip(
            'SANS OBJET : `git` ou `ruff` manque ici. Le discriminant par nom de '
            "journal reste le seul filet — ce skip dit qu'on mesure MOINS, pas "
            "qu'il n'y a rien a signaler.")

    racine = _racine_du_depot(_dossier_des_patchs())
    fautes = []
    for patch in patchs:
        if QUARANTAINE in patch.name:
            continue
        cible = _cible(patch)
        copie = tmp_path / patch.stem
        copie.mkdir(parents=True, exist_ok=True)
        destination = copie / pathlib.Path(cible).name
        shutil.copy(racine / cible, destination)

        applique = subprocess.run(
            ['git', 'apply', '--unsafe-paths', f'--directory={copie}',
             '-p2', str(patch)],
            capture_output=True, text=True, cwd=racine)
        if applique.returncode != 0:
            # Un patch qui ne s'applique pas est un autre sujet — il est couvert
            # par `git apply --check` ailleurs. On le DIT sans le compter comme
            # une faute F821, qu'on n'a pas pu mesurer.
            fautes.append(f'{patch.name} : NON APPLIQUE ici, F821 non mesure '
                          f'({applique.stderr.strip()[:120]})')
            continue

        lint = subprocess.run(['ruff', 'check', '--select', 'F821',
                               '--no-cache', str(destination)],
                              capture_output=True, text=True)
        if lint.returncode not in (0,):
            fautes.append(f'{patch.name} : {lint.stdout.strip()[:300]}')

    # Les patchs non appliques sont RAPPORTES, pas tus : « je n'ai pas pu
    # mesurer » n'est pas « rien a signaler ».
    reels = [f for f in fautes if 'NON APPLIQUE' not in f]
    if fautes and not reels:
        pytest.skip('F821 non mesurable sur ces patchs :\n  - '
                    + '\n  - '.join(fautes))
    assert not reels, ('F821 — nom non defini apres application :\n  - '
                       + '\n  - '.join(reels))
