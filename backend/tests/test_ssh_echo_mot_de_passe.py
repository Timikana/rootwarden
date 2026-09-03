"""
Filtre de l'echo PTY du mot de passe root dans `execute_as_root_stream`.

Le defaut que ces tests figent : le mot de passe est echote DEUX fois par le
pseudo-terminal, et le correctif precedent, qui jetait « la premiere ligne »,
n'en jetait qu'un. Le second traversait et arrivait en clair dans le flux rendu
au navigateur — donc a l'ecran, dans le journal d'execution du module `update/`.

Mesure a l'origine de ces tests, sur une machine du parc
(`sudo -S -p '' sh -c 'id -u'`, PTY, ecriture immediate du mot de passe),
morceaux bruts lus sur le canal :

    morceau 1 : '<mot de passe>\\r\\n'
    morceau 2 : '<mot de passe>\\r\\n'
    morceau 3 : '0\\r\\n'

Ces tests assertent le comportement ATTENDU — aucune ligne egale au secret ne
sort, quel que soit son rang — et non le comportement de l'implementation.

Le filtre PRESERVE les fins de ligne du flux (`\\r\\n` du pseudo-terminal) :
il retire les lignes qui sont le secret, et ne reecrit rien d'autre.
"""
import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# `conftest.py` remplace `ssh_utils` par un MagicMock pour que les tests des
# routes n'ouvrent aucune session SSH. Ici, c'est justement le VRAI filtre qu'on
# veut eprouver : on charge le fichier directement, sans passer par
# `sys.modules`. Sans cela, l'appel rendrait un mock — et un mock se laisse
# depaqueter en silence, ce qui donnerait un test toujours vert.
_CHEMIN = Path(__file__).resolve().parents[1] / 'ssh_utils.py'
_spec = importlib.util.spec_from_file_location('ssh_utils_reel', _CHEMIN)
_ssh_utils_reel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ssh_utils_reel)

filtre_echo_mot_de_passe = _ssh_utils_reel.filtre_echo_mot_de_passe

SECRET = 'M0tDeP@sse-Root-2026'


def passe(morceaux, secret=SECRET, **bornes):
    """Fait passer des morceaux dans le filtre et rend le flux emis."""
    sans_echo, fin_de_tampon = filtre_echo_mot_de_passe(secret, **bornes)
    sortie = ''.join(sans_echo(m) for m in morceaux)
    return sortie + fin_de_tampon()


def test_echo_double_le_defaut_mesure():
    """Les DEUX echos disparaissent ; la sortie de la commande reste entiere."""
    flux = passe(['%s\r\n' % SECRET, '%s\r\n' % SECRET, '0\r\n'])
    assert SECRET not in flux
    assert flux == '0\r\n'


def test_echo_simple():
    flux = passe(['%s\r\n' % SECRET, 'sortie\r\n'])
    assert SECRET not in flux
    assert flux == 'sortie\r\n'


def test_aucun_echo_rien_n_est_perdu():
    """Sans echo, le filtre ne doit rien retirer."""
    flux = passe(['premiere ligne\r\n', 'seconde ligne\r\n'])
    assert flux == 'premiere ligne\r\nseconde ligne\r\n'


def test_echo_scinde_sur_une_frontiere_de_lecture():
    """Un echo coupe en deux lectures est reconstitue avant comparaison.

    C'est ce cas qu'un simple `replace` ne savait pas traiter.
    """
    moitie = len(SECRET) // 2
    flux = passe([SECRET[:moitie], SECRET[moitie:] + '\r\n', 'sortie\r\n'])
    assert SECRET not in flux
    assert flux == 'sortie\r\n'


def test_invite_de_su_avant_l_echo():
    """`su` ecrit une invite ; elle est conservee, l'echo qui suit est jete."""
    flux = passe(['Mot de passe : \r\n', '%s\r\n' % SECRET, 'sortie\r\n'])
    assert SECRET not in flux
    assert flux == 'Mot de passe : \r\nsortie\r\n'


def test_une_ligne_qui_contient_le_secret_sans_l_etre_passe():
    """Le filtre vise les lignes qui SONT le secret, pas celles qui le citent.

    Aucun cas reel connu ; le test dit ce que le filtre fait, pour qu'un
    changement de regle soit un choix et non un accident.
    """
    ligne = 'echec pour %s ici' % SECRET
    flux = passe([ligne + '\r\n'])
    assert flux == ligne + '\r\n'


def test_la_fenetre_est_bornee_en_lignes():
    """Passe la fenetre, le filtre laisse tout passer — le flux doit couler."""
    morceaux = ['ligne %d\r\n' % i for i in range(6)]
    morceaux.append('%s\r\n' % SECRET)
    flux = passe(morceaux, lignes_surveillees=3)
    assert SECRET in flux, "hors fenetre, le filtre ne retient plus rien"


def test_la_fenetre_est_bornee_en_octets():
    """Sans saut de ligne, le tampon ne doit pas retenir le flux indefiniment."""
    flux = passe(['x' * 500], octets_surveilles=100)
    assert flux == 'x' * 500


def test_fragment_final_sans_saut_de_ligne():
    """Le dernier fragment est emis, sauf s'il n'est que le secret."""
    assert passe(['%s\r\n' % SECRET, 'sans fin de ligne']) == 'sans fin de ligne'
    assert passe(['%s\r\n' % SECRET, SECRET]) == ''


def test_secret_vide_desactive_le_filtre():
    flux = passe(['une ligne\r\n'], secret='')
    assert flux == 'une ligne\r\n'


def test_le_secret_n_apparait_jamais_meme_partiellement():
    """Aucun fragment de six caracteres du secret ne doit sortir."""
    flux = passe(['%s\r\n' % SECRET, '%s\r\n' % SECRET, 'Debian GNU/Linux 12\r\n'])
    for depart in range(len(SECRET) - 5):
        assert SECRET[depart:depart + 6] not in flux
