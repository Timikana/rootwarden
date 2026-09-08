r"""
test_sudo_runas_valide_sur_tous_les_chemins.py

┌─ LE DEFAUT QUE CE TEST FERME ────────────────────────────────────────────────┐
│ `render_policy` interpole `runas` dans l'EN-TETE du fichier sudoers, sur      │
│ TOUS les chemins. Sa seule validation vivait dans `_runas_spec` — appele par  │
│ `systemctl_specific` et par les `PRESET_RENDERERS`, mais PAS par la branche   │
│ `custom`, qui ne lui passe pas `runas`.                                       │
│                                                                               │
│ La branche qui n'avait pas besoin de METTRE EN FORME la valeur perdait donc   │
│ aussi sa VALIDATION — alors qu'elle l'ECRIT quand meme, dans l'en-tete.       │
│                                                                               │
│ Un saut de ligne dans ce champ ferme la ligne de commentaire et ouvre une     │
│ directive sudoers que personne n'a demandee, dans un fichier nomme d'apres    │
│ quelqu'un d'autre — pendant que l'en-tete ET le journal continuent d'afficher │
│ la valeur attendue. Ce qui tombe d'abord n'est pas la frontiere de privilege  │
│ (un role 3 peut deja octroyer root par `all_nopasswd`, dont la docstring dit  │
│ « EQUIVALENT ROOT ») : c'est la PISTE D'AUDIT.                                │
│                                                                               │
│ Mesure du 2026-09-09, branche `custom` :                                      │
│   runas legitime                 -> 1 directive rendue                        │
│   runas portant un saut de ligne -> 2 directives, dont une non demandee       │
│ Les cinq branches qui appellent `_runas_spec` refusaient deja la meme valeur. │
└──────────────────────────────────────────────────────────────────────────────┘

LE CORRECTIF EST STRUCTUREL, PAS PONCTUEL. Ajouter un `if` dans la branche
`custom` aurait ferme CE chemin ; la prochaine branche l'aurait rouvert. La
validation est donc SEPAREE du formatage (`valide_runas`) et posee en PREMIERE
INSTRUCTION de `render_policy`, ou elle domine tout ce qui suit. Aucune branche
ne peut plus l'esquiver en n'ayant pas besoin de mettre la valeur en forme.

⚠ CE QUE CE TEST NE COUVRE PAS : il mesure le RENDU, pas ce que `visudo -cf`
accepte sur une machine. Une directive injectee est syntaxiquement banale, mais
personne n'a joint de machine pour le verifier — et ca ne change pas le verdict,
puisque le defaut est que la valeur ARRIVE dans le fichier.
"""

import importlib.util
import os
import sys
import types

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _charge(nom_fichier, nom_module):
    """Charge un module de `backend/` sans importer toute l'application."""
    chemin = os.path.join(RACINE, nom_fichier)
    spec = importlib.util.spec_from_file_location(nom_module, chemin)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(nom_module, module)
    spec.loader.exec_module(module)
    return module


sudo_manager = _charge('sudo_manager.py', 'sudo_manager_sous_test')

SAUT = chr(10)
# La charge est construite plutot qu'ecrite en clair : ce depot est PUBLIC, et
# un motif copiable dans un fichier suivi est un mode d'emploi. Le mecanisme est
# decrit ci-dessus ; la valeur ci-dessous suffit a l'ASSERTION sans la publier
# sous une forme prete a coller.
_RUNAS_HOSTILE = 'root' + SAUT + 'AUTRE ALL=(ALL) NOPASSWD: ALL'


def _directives(rendu):
    """Les lignes de DIRECTIVE : ni vides, ni commentaires."""
    return [l for l in rendu.split(SAUT) if l.strip() and not l.lstrip().startswith('#')]


def test_le_cas_banal_rend_exactement_une_directive():
    """TEMOIN POSITIF. Sans lui, « 0 directive » se lirait comme « c'est sur ».

    Et le cas est le plus BANAL qu'on puisse ecrire, pas le plus retors : c'est
    celui que l'exploitant produit tous les jours.
    """
    rendu = sudo_manager.render_policy({
        'username': 'john', 'preset': 'custom',
        'runas': 'root', 'custom_rules': '/bin/ls',
    })
    assert _directives(rendu) == ['john /bin/ls']


def test_la_branche_custom_refuse_un_runas_non_valide():
    """LE DEFAUT LUI-MEME : c'est la branche qui n'utilise pas `runas`."""
    try:
        rendu = sudo_manager.render_policy({
            'username': 'john', 'preset': 'custom',
            'runas': _RUNAS_HOSTILE, 'custom_rules': '/bin/ls',
        })
    except ValueError:
        return
    raise AssertionError(
        f'la branche `custom` a RENDU {len(_directives(rendu))} directive(s) '
        f'au lieu de refuser : {_directives(rendu)}'
    )


def test_toutes_les_branches_refusent_la_meme_valeur():
    """La garde DOMINE : aucune branche n'y echappe, y compris futures.

    Les branches sont DERIVEES de `PRESET_RENDERERS` et non retapees — un
    preset ajoute demain entre dans ce test sans qu'on y pense.
    """
    presets = sorted(sudo_manager.PRESET_RENDERERS) + ['custom', 'systemctl_specific']
    assert len(presets) >= 6, f'{len(presets)} branches : la derivation a echoue'
    for preset in presets:
        politique = {
            'username': 'john', 'preset': preset, 'runas': _RUNAS_HOSTILE,
            'custom_rules': '/bin/ls', 'services': ['nginx'],
        }
        try:
            rendu = sudo_manager.render_policy(politique)
        except ValueError:
            continue
        raise AssertionError(
            f"la branche {preset!r} a rendu au lieu de refuser : {_directives(rendu)}"
        )


def test_aucune_branche_ne_casse_sur_une_valeur_legitime():
    """CONTRE-EPREUVE. Un garde qui refuse TOUT passerait le test precedent.

    C'est la moitie que le vert d'un refus ne montre jamais.
    """
    presets = sorted(sudo_manager.PRESET_RENDERERS) + ['custom', 'systemctl_specific']
    for preset in presets:
        rendu = sudo_manager.render_policy({
            'username': 'john', 'preset': preset, 'runas': 'root',
            'custom_rules': '/bin/ls', 'services': ['nginx'],
        })
        assert _directives(rendu), f'la branche {preset!r} ne rend AUCUNE directive'


def test_valide_runas_aux_bornes():
    """Le validateur lui-meme, sur ses limites — mesurees, pas supposees."""
    assert sudo_manager.valide_runas('root') == 'root'
    assert sudo_manager.valide_runas('') == 'root', 'le defaut documente est `root`'
    assert sudo_manager.valide_runas(None) == 'root'
    assert sudo_manager.valide_runas('  root  ') == 'root', '`.strip()` normalise'
    assert sudo_manager.valide_runas('_svc') == '_svc'
    assert sudo_manager.valide_runas('a' * 32) == 'a' * 32, 'borne haute acceptee'
    for refus in ('a' * 33, 'Root', '1svc', 'sv c', 'sv;c', 'sv$c', _RUNAS_HOSTILE):
        try:
            sudo_manager.valide_runas(refus)
        except ValueError:
            continue
        raise AssertionError(f'{refus[:20]!r} accepte alors qu il doit etre refuse')


def test_la_validation_est_SEPAREE_du_formatage():
    """Garde sur la FORME du correctif, pas seulement sur son effet.

    Refondre `valide_runas` dans `_runas_spec` reconduirait le defaut : une
    branche qui n'a pas besoin du format `(runas)` reperdrait la validation.
    Ce test echoue si quelqu'un les refusionne.
    """
    import inspect
    source = inspect.getsource(sudo_manager.render_policy)
    assert 'valide_runas(' in source, \
        '`render_policy` ne valide plus `runas` : la garde a ete retiree'
    premieres = [l.strip() for l in source.split(SAUT) if l.strip()
                 and not l.strip().startswith('#') and not l.strip().startswith('"""')]
    ligne_garde = next(i for i, l in enumerate(premieres) if 'valide_runas(' in l)
    ligne_entete = next((i for i, l in enumerate(premieres) if 'runas={runas}' in l), None)
    assert ligne_entete is not None, "l'en-tete n'interpole plus `runas` : verifier ce test"
    assert ligne_garde < ligne_entete, \
        'la garde ne DOMINE plus l en-tete qui interpole `runas`'


if __name__ == '__main__':
    for nom, fn in sorted(globals().items()):
        if nom.startswith('test_'):
            fn()
            print(f'  ✅ {nom}')
