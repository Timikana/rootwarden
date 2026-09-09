r"""
test_ssh_audit_include_traversal.py

┌─ LE DEFAUT QUE CE TEST FERME ────────────────────────────────────────────────┐
│ `get_sshd_config` suit les directives `Include` du `sshd_config` de la        │
│ machine auditee et fait un `cat` EN ROOT sur chaque chemin. Le seul filtre    │
│ etait `^/etc/ssh/[a-zA-Z0-9_./*-]+$` — dont la classe contient `.` et `/`,    │
│ donc `..` y est CONSTRUCTIBLE.                                                │
│                                                                               │
│   /etc/ssh/sshd_config.d/*.conf         ACCEPTE   <- temoin positif           │
│   /etc/ssh/../../etc/shadow             ACCEPTE   ⚠                           │
│   /etc/ssh/x/../../../root/.ssh/id_rsa  ACCEPTE   ⚠                           │
│                                                                               │
│ ET LE JOURNAL DISAIT DEJA « path traversal? ». L'auteur visait ce risque ;    │
│ la classe ne le couvrait pas. Un journal qui NOMME une protection que le code  │
│ ne fournit pas se relit comme une preuve.                                     │
└──────────────────────────────────────────────────────────────────────────────┘

SEVERITE, BORNEE SERRE — ce n'est PAS une faille :
  `include_path` vient d'une ligne `Include` du `sshd_config` DE LA MACHINE
  AUDITEE. Pour la controler il faut deja pouvoir ecrire `/etc/ssh/sshd_config`
  sur cette machine, c'est-a-dire y etre root — et le portail y est deja root,
  puisqu il fait `execute_as_root`. Aucune frontiere de confiance n'est franchie,
  et il n'y a pas d'injection de shell : apostrophe, espace, `;`, `$(` sont
  refuses par la classe.
  C'est de la DEFENSE EN PROFONDEUR, et de la meme famille que les quatre
  gardes de `DOSSIER-62` : le motif nomme n'est pas la garde effective — sauf
  qu'ici la garde effective n'existait pas.

Trouve par `gestion-ssh-key-c1` le 2026-09-09, et trouve par une sonde FAUSSE :
sa sonde appariait la sous-chaine `_PATH_RE` et a attrape `_INCLUDE_PATH_RE`,
un autre motif dans un autre module. Elle l'a dit avant le reste.
"""

import importlib.util
import os
import re
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _source_de_la_fonction():
    """Le texte de `get_sshd_config`, lu dans l'arbre.

    Le module importe `paramiko` et exige des variables d'environnement : on lit
    la SOURCE plutot que d'importer, pour que ce test tourne partout. La contre-
    partie est dite : il mesure le TEXTE, pas l'execution — et c'est pour ca que
    le motif et la garde sont ensuite EXTRAITS et joues pour de vrai.
    """
    with open(os.path.join(RACINE, 'ssh_audit.py'), encoding='utf-8') as fh:
        source = fh.read()
    debut = source.index('def get_sshd_config')
    suite = source.find('\ndef ', debut + 1)
    return source[debut:suite if suite != -1 else None]


def _motif_et_garde():
    """Extrait le motif ET la garde de segments, DEPUIS la source.

    Retapes, ils mesureraient ma memoire ; extraits, ils mesurent le fichier.
    """
    corps = _source_de_la_fonction()
    m = re.search(r"_INCLUDE_PATH_RE\s*=\s*re\.compile\(r'([^']+)'\)", corps)
    assert m, 'le motif _INCLUDE_PATH_RE n a pas ete trouve dans get_sshd_config'
    garde = "'..' in include_path.split('/')" in corps
    return re.compile(m.group(1)), garde


def _accepte(chemin):
    motif, garde = _motif_et_garde()
    if not motif.fullmatch(chemin):
        return False
    if garde and '..' in chemin.split('/'):
        return False
    return True


def test_le_temoin_positif_passe():
    """Sans lui, un garde qui refuse TOUT passerait tous les autres tests."""
    for legitime in ('/etc/ssh/sshd_config.d/*.conf',
                     '/etc/ssh/sshd_config.d/50-cloud.conf',
                     '/etc/ssh/ssh_config.d/*'):
        assert _accepte(legitime), f'{legitime!r} refuse alors qu il est legitime'


def test_la_remontee_de_repertoire_est_refusee():
    """LE DEFAUT. La classe rend `..` constructible ; la garde le refuse."""
    for traversee in ('/etc/ssh/../../etc/shadow',
                      '/etc/ssh/x/../../../root/.ssh/id_rsa',
                      '/etc/ssh/..',
                      '/etc/ssh/a/../b'):
        assert not _accepte(traversee), \
            f'{traversee!r} ACCEPTE : la remontee de repertoire passe'


def test_la_garde_porte_sur_les_SEGMENTS_et_non_la_sous_chaine():
    """`/etc/ssh/x..y` n'est PAS une remontee : il doit rester accepte.

    Une garde `'..' in chemin` aurait refuse ce nom parfaitement valide. Le test
    de segments est celui de `sftp_manager._validate_path`, et c'est le bon.
    """
    assert _accepte('/etc/ssh/x..y'), \
        'la garde refuse un nom contenant `..` hors segment : elle est trop large'


def test_aucune_injection_de_shell_n_est_exprimable():
    """Le chemin va dans `cat {include_path}` : la classe doit tout barrer."""
    for hostile in ("/etc/ssh/a'b", '/etc/ssh/a b', '/etc/ssh/a;id',
                    '/etc/ssh/$(id)', '/etc/ssh/`id`', '/etc/ssh/a|b',
                    '/etc/ssh/a\nid'):
        assert not _accepte(hostile), f'{hostile!r} accepte : un metacaractere passe'


def test_le_prefixe_reste_obligatoire():
    """Hors `/etc/ssh/`, tout est refuse — c'est la premiere moitie du filtre."""
    for dehors in ('/etc/passwd', '/root/.ssh/id_rsa', 'etc/ssh/x', '/tmp/x'):
        assert not _accepte(dehors), f'{dehors!r} accepte hors du prefixe'


def test_les_deux_refus_ont_des_libelles_DISTINCTS():
    """Un libelle qui affirme la mauvaise cause coute une enquete.

    Un motif non conforme et une remontee de repertoire ne font pas chercher au
    meme endroit. L'ancien message unique disait « path traversal? » pour les
    DEUX — et il le disait pour un cas qu'il ne detectait pas.
    """
    corps = _source_de_la_fonction()
    avertissements = re.findall(r'_log\.warning\("Include path rejected \(([^)]*)\)', corps)
    assert len(avertissements) == 2, \
        f'{len(avertissements)} libelle(s) de refus, 2 attendus : {avertissements}'
    assert len(set(avertissements)) == 2, \
        f'les deux refus portent le MEME libelle : {avertissements}'
    assert not any('traversal?' in a for a in avertissements), \
        'un libelle affirme encore une detection par un point d interrogation'


def test_la_garde_est_bien_PRESENTE_dans_la_fonction():
    """Garde sur la FORME : le test ci-dessus passerait sans elle, a vide.

    `_accepte` n'applique la garde que si elle existe dans la source. Sans cette
    assertion, retirer la garde rendrait `_accepte` permissif ET les tests
    verts — une universelle negative est vraie a vide.
    """
    _, garde = _motif_et_garde()
    assert garde, \
        "la garde `'..' in include_path.split('/')` a disparu de get_sshd_config"


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
