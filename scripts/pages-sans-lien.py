#!/usr/bin/env python3
"""Detecte les PAGES du portage qu'aucune vue ne lie — donc injoignables.

Ne remplace pas une suite E2E : c'est un controle STATIQUE, et il vit ici parce
qu'une page injoignable ne se voit par aucune assertion de rendu — la page
s'affiche parfaitement, personne n'y arrive.

NE dit RIEN sur ce qui est atteint par une redirection de controleur, par un
`fetch`, ou par un lien construit a l'execution : ces trois cas sont declares
dans TOLERES ci-dessous, avec leur raison.

Origine : le 2026-09-03, `notifications.reglages` a ete trouve porte, garde
`role:3`, et lie de NULLE PART. La sonde qui avait conclu « il n'y a pas de
troisieme portage injoignable » enumerait par MODULE et non par ROUTE :
`notifications` est lie depuis le socle, `notifications.reglages` ne l'est pas,
et le prefixe partage rendait la confusion invisible.

Sortie : code 0 si l'inventaire correspond a TOLERES, 1 sinon — donc ce script
ROUGIT aussi bien quand une page devient injoignable que quand une page toleree
cesse de l'etre. Le second sens est volontaire : il force a retirer la
tolerance, donc a la relire.
"""
import glob
import io
import os
import re
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Pages sans lien entrant, TOLEREES, avec la raison de chacune ─────────────
#
# Toute entree ici est une DETTE ou une exception justifiee. Une page qui n'y
# figure pas et n'a pas de lien fait echouer ce script.
TOLERES = {
    'cgu':                       'redirection du controleur apres le second facteur',
    'second-facteur':            "redirection du flux d'authentification",
    'second-facteur.enrolement': "redirection du flux d'authentification",
    'tickets':                   'lien construit a l\'execution par la recherche '
                                 '(search.py emet /tickets/index.php, LiensLegacy le traduit)',
    'notifications.reglages':    'DETTE : injoignable, aucune vue ne la lie — '
                                 'trouvee le 2026-09-03, le lien reste a poser',
}


def lire(chemin):
    try:
        return io.open(chemin, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''


def routes_get():
    """Routes GET nommees SANS parametre."""
    web = lire(os.path.join(RACINE, 'laravel/routes/web.php'))
    trouvees = set()
    for m in re.finditer(r"Route::get\(\s*'(/[^']*)'.*?->name\('([a-z0-9._-]+)'\)", web, re.S):
        if '{' not in m.group(1):
            trouvees.add(m.group(2))
    return trouvees


def _vue_de(dossier, nom):
    """Chemin de la vue dediee a cette route, ou None.

    QUATRE conventions, parce que le depot en emploie plusieurs et qu'une seule
    ne suffisait pas : `second-facteur` vit dans `auth/second-facteur.blade.php`
    et `second-facteur.enrolement` dans `auth/enrolement.blade.php`.
    On cherche donc aussi le NOM DE BASE ou qu'il soit sous `views/`.
    """
    bases = [nom.replace('.', '-'), nom.replace('.', '/'), nom.split('.')[-1]]
    for b in bases:
        direct = os.path.join(dossier, b + '.blade.php')
        if os.path.exists(direct):
            return direct
    for b in bases:
        trouves = glob.glob(os.path.join(dossier, '**', os.path.basename(b) + '.blade.php'),
                            recursive=True)
        if trouves:
            return trouves[0]
    return None


def pages():
    """Parmi les routes GET, celles qui sont des PAGES et non des points d'appel.

    Le discriminant est l'existence d'une VUE DEDIEE. Sans lui, ce script
    signalait huit routes comme injoignables alors que ce sont des cibles de
    `fetch` : `scan-cve.suivi`, `fail2ban.portee`, `journal-audit.verifier`…
    Une cible de `fetch` n'a pas a etre LIEE, elle a a etre APPELEE — et ce
    n'est pas la meme propriete.

    Deux conventions de nommage de vue sont acceptees, parce que le depot
    emploie les deux : `notifications.reglages` -> `notifications-reglages`,
    et un eventuel `auth/xxx` -> `auth/xxx`.
    """
    dossier = os.path.join(RACINE, 'laravel/resources/views')
    retenues = set()
    for n in routes_get():
        if _vue_de(dossier, n):
            retenues.add(n)
    return retenues


def dans_navigation(noms):
    nav = lire(os.path.join(RACINE, 'laravel/app/Support/Navigation.php'))
    return {n for n in noms if re.search(r"'route'\s*=>\s*'%s'" % re.escape(n), nav)}


def vue_propre(nom):
    """Sa propre vue — meme resolveur que `pages()`, pour qu'on ne puisse pas
    exclure un fichier different de celui qui a fait retenir la route."""
    return _vue_de(os.path.join(RACINE, 'laravel/resources/views'), nom) or ''


def liens_entrants(nom):
    """Vues AUTRES que la sienne qui posent un href/action vers cette route.

    L'exclusion de la vue propre est essentielle : un compte de mentions inclut
    les auto-references — `serveurs` en portait une centaine, presque toutes
    dans son propre gabarit, ce qui faisait passer la page pour liee.
    """
    motif = re.compile(r"""(href|action|data-action)\s*=\s*["']?\{\{\s*route\(\s*'%s'"""
                       % re.escape(nom))
    propre = os.path.abspath(vue_propre(nom))
    sources = []
    for v in glob.glob(os.path.join(RACINE, 'laravel/resources/views/**/*.blade.php'),
                       recursive=True):
        if os.path.abspath(v) == propre:
            continue
        if motif.search(lire(v)):
            sources.append(v.split('views/')[-1])
    return sources


def main():
    toutes = pages()
    if not toutes:
        print('ECHEC : aucune route GET nommee trouvee — instrument casse, pas depot vide')
        return 1

    menu = dans_navigation(toutes)
    hors_menu = sorted(toutes - menu)

    sans_lien, avec_lien = [], {}
    for n in hors_menu:
        l = liens_entrants(n)
        (avec_lien.setdefault(n, l) if l else sans_lien.append(n))

    print('pages (route GET nommee + vue dediee) : %d' % len(toutes))
    print('  (les routes SANS vue dediee sont des points d\'appel : ecartees)')
    print('  dans le menu                      : %d' % len(menu))
    print('  hors menu, avec un lien entrant   : %d' % len(avec_lien))
    print('  hors menu, SANS lien entrant      : %d' % len(sans_lien))
    print()

    inattendues = [n for n in sans_lien if n not in TOLERES]
    guéries = [n for n in TOLERES if n not in sans_lien and n in toutes]
    disparues = [n for n in TOLERES if n not in toutes]

    for n in sans_lien:
        print('  %-30s %s' % (n, TOLERES.get(n, '*** INATTENDUE ***')))

    code = 0
    if inattendues:
        print()
        print('ECHEC — page(s) injoignable(s) NON declaree(s) : %s' % ', '.join(inattendues))
        print('  Poser un lien, ou inscrire la page dans TOLERES avec sa raison.')
        code = 1
    if guéries:
        print()
        print('ECHEC — page(s) toleree(s) qui ont MAINTENANT un lien : %s' % ', '.join(guéries))
        print('  Retirer ces entrees de TOLERES : la dette est payee.')
        for n in guéries:
            print('     %-28s lie depuis %s' % (n, ', '.join(avec_lien.get(n, []))))
        code = 1
    if disparues:
        print()
        print('ECHEC — TOLERES cite des routes qui n\'existent plus : %s' % ', '.join(disparues))
        code = 1
    if code == 0:
        print('OK — l\'inventaire correspond exactement aux tolerances declarees.')
    return code


if __name__ == '__main__':
    sys.exit(main())
