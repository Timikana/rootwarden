#!/usr/bin/env python3
"""Un chemin de passerelle est-il APPELE par le portage ?

    ./scripts/geste-porte.py /deploy /logs /preflight_check

⚠ CHAQUE MECANISME CI-DESSOUS A ETE TROUVE PAR UNE CONTRE-EPREUVE QUI ECHOUAIT,
  jamais par imagination. Le jeu de temoins est en bas du fichier : le lancer
  AVANT de croire un verdict. **Une sonde qui rend « absent » sur un geste qu'on
  sait porte a un mecanisme de plus a decouvrir.**


Le predicat porte sur le CONTEXTE DE PASSERELLE, jamais sur un caractere :

  ancre stricte (delimiteur a gauche)  -> rate `${API_URL}/deploy` (avant : `}`)
  ancre tolerante (`}` accepte)        -> attrape `/supervision/{$p}/deploy`
  racine ADJACENTE seule               -> rate `lit('/bashrc/deploy')`, ou la
                                          racine est DANS le helper appele

La racine peut donc etre a UNE INDIRECTION du chemin, et cette indirection est
DERIVEE du fichier lu, pas enumeree : on cherche les fonctions dont le corps
fait `fetch(<racine> + <parametre>)`, et leur nom devient une racine de plus.
"""
import re, sys, io, os

RACINES_TEXTE = [
    r"PASSERELLE\s*\+\s*['\"]",
    r"\$\{\s*window\.API_URL\s*\}",
    r"\$\{\s*API_URL\s*\}",
    r"['\"]/api/gateway",
]
DECLARATIFS = ('RoutesBackend.php', 'AutorisationsPasserelle.php')
RACINE_JS = r"(?:PASSERELLE|window\.API_URL|API_URL)"

def helpers(source):
    """Noms des fonctions qui encapsulent la racine : `fetch(RACINE + param)`."""
    noms = set()
    for m in re.finditer(r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)", source):
        nom, params = m.group(1), m.group(2)
        premier = (params.split(',')[0] or '').strip()
        if not premier:
            continue
        corps = source[m.end():m.end() + 800]
        if re.search(r"fetch\s*\(\s*" + RACINE_JS + r"\s*\+\s*" + re.escape(premier) + r"\b", corps):
            noms.add(nom)
    return noms

def constantes(source, chemin):
    """Constantes valant `chemin` ET concatenees a une racine de passerelle.

    Le nom seul ne suffit pas : une constante qui porte le chemin sans jamais
    toucher la racine n'est pas un appel. On exige les DEUX.
    """
    noms = set()
    for m in re.finditer(r"(?:var|const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*['\"]" + re.escape(chemin) + r"['\"]", source):
        nom = m.group(1)
        if re.search(RACINE_JS + r"\s*\+\s*" + re.escape(nom) + r"\b", source) \
           or re.search(re.escape(nom) + r"\s*\+\s*" + RACINE_JS + r"\b", source):
            noms.add(nom)
    return noms


def appels(chemin, racine='laravel'):
    trouves = []
    adjacent = re.compile('(?:' + '|'.join(RACINES_TEXTE) + ')' + re.escape(chemin) + r"(?![\w/-])")
    for base, _, fichiers in os.walk(racine):
        if '_deprecated' in base or '/vendor/' in base or '/node_modules/' in base:
            continue
        for f in fichiers:
            if not f.endswith(('.js', '.php')) or f in DECLARATIFS:
                continue
            p = os.path.join(base, f)
            try:
                src = io.open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            motifs = [adjacent]
            for h in helpers(src):                       # l'indirection, DERIVEE
                motifs.append(re.compile(re.escape(h) + r"\s*\(\s*['\"]" + re.escape(chemin) + r"(?![\w/-])"))
            # 3e mecanisme : le chemin est lie a une CONSTANTE, elle-meme
            # concatenee a la racine. Il n'est alors ni adjacent, ni argument.
            for cste in constantes(src, chemin):
                motifs.append(re.compile(r"\b" + re.escape(cste) + r"\b\s*=\s*['\"]" + re.escape(chemin)))
            for i, l in enumerate(src.split('\n'), 1):
                for mo in motifs:
                    if mo.search(l):
                        trouves.append((p, i, l.strip()[:84])); break
    return trouves

if __name__ == '__main__':
    for chemin in sys.argv[1:]:
        r = appels(chemin)
        print('  %-24s %s' % (chemin, 'APPELE' if r else 'ABSENT'))
        for p, i, l in r:
            print('      %s:%d  %s' % (p, i, l))


# ═══ LE JEU DE TEMOINS ══════════════════════════════════════════════════════
#
# Les six premiers sont portes, verifies independamment de cette sonde ; les
# trois derniers sont absents, dont un DELIBEREMENT inexprimable. Un verdict de
# cette sonde ne vaut rien si ce jeu ne passe pas.
#
#   ./scripts/geste-porte.py /preflight_check /logs /policy/rollback \
#       /bashrc/deploy /bashrc/backups /server_user_remove_key      # APPELE x6
#   ./scripts/geste-porte.py /zzz-invente /supervision /policy/deployments
#                                                                   # ABSENT x3
#
# Les trois absences sont STRUCTURELLES, et c'est voulu :
#   `/zzz-invente`        n'existe nulle part ;
#   `/supervision`        la route reelle est `/supervision/<plateforme>/deploy`,
#                         et c'est elle qui piegeait l'ancre tolerante ;
#   `/policy/deployments` retiree du backend par `80c2057` et non restauree.
#
# ⚠⚠ UN TEMOIN DONT LE STATUT DEPEND D'UNE DECISION SE PERIME QUAND LA DECISION
# BOUGE. Ce jeu portait `/bashrc/prerequisites` comme temoin negatif, au motif
# qu'il etait « inexprimable par decision ». **Le 2026-09-07 a 21:46, une session
# l'a porte au titre de l'iso-perimetre** — la decision a change, et le temoin
# est devenu FAUX sans que rien dans l'outil ne bouge. La sonde, elle, avait
# raison : elle a trouve l'appel a `bashrc.js:280`.
#
# *Un temoin doit etre absent par CONSTRUCTION, jamais par arbitrage.* Sinon le
# jour ou il rougit, on soupçonne l'instrument au lieu de lire ce qu'il dit.
