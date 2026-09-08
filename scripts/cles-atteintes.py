#!/usr/bin/env python3
r"""Les cles d'un catalogue i18n sont-elles ATTEINTES, et par quel chemin ?

    ./scripts/cles-atteintes.py sftp
    ./scripts/cles-atteintes.py sftp --domaine 'sftp.f_=sftp_only,password,tcp,agent,x11'

⚠ CE QUE CET OUTIL REFUSE DE FAIRE, ET C'EST SON POINT PRINCIPAL.

Quand il rencontre une cle CONSTRUITE — `__('sftp.f_' . $cle)` — il ne devine pas
les valeurs possibles de la variable. **Il s'arrete et les demande.** Une sonde
qui compte le prefixe `sftp.f_` comme une cle rend un verdict faux dans les deux
sens : elle signale une cle « citee mais absente » qui n'existe pas, et elle
declare « atteintes » des cles qui ne le sont pour aucune valeur reelle.

    coût du manque : `__()` rend LE NOM DE LA CLE quand elle est absente.
    Un identifiant nu s'affiche a l'utilisateur — et c'est un titre NON VIDE,
    donc satisfaisant toute assertion de forme. Une epreuve qui mesure la FORME
    d'un libelle ne peut pas voir qu'il ne DESIGNE rien.

══ LES QUATRE CHEMINS PAR LESQUELS UNE CLE EST ATTEINTE ═══════════════════

    LITTERALE   `__('sftp.titre')`                    comptage direct
    CONSTRUITE  `__('sftp.etat_' . $h->status)`       domaine a ENUMERER A SA SOURCE
    CURATEE     `foreach ([...] as $c) __('sftp.'.$c)` liste lue dans le code
    ORPHELINE   aucun des trois

Une cle CURATEE n'est pas orpheline : elle voyage dans un bloc JSON vers un
script. La confondre avec une orpheline ferait retirer un libelle en service.

══ TROIS PIEGES D'INSTRUMENT, PAYES ET FERMES ICI ═════════════════════════

1. POPULATION PAR CONTENU, jamais par nom de fichier. Le consommateur de `sftp`
   s'appelle `acces-sftp.blade.php` : un glob `sftp*.blade.php` rend « module
   mort » sur un module vivant.

2. COMMENTAIRES DEPOUILLES A CHAQUE FOIS, sans se demander si ce fichier-la en
   contient. Cinq syntaxes : `/* */`, `//`, `#`, `{{-- --}}`, docblock. Un
   commentaire qui CITE une cle en prose la fait compter comme atteinte.

3. ANCRE A GAUCHE. `t\('…'\)` sans ancre matche la fin de
   `document.createElemen` + `t('article')` : six faux positifs sur un fichier.
   L'ancre est `(?<![A-Za-z0-9_$.])`.

══ ET UN TEMOIN QUI DOIT RENDRE NON-ZERO ═════════════════════════════════

« 0 cle orpheline » et « ma sonde n'a rien lu » sont la MEME sortie. L'outil
verifie donc qu'il a lu des fichiers, trouve des cles, et atteint au moins une
cle connue — et il le DIT dans sa sortie, pas seulement en interne.
"""
import io, os, re, sys, pathlib

RACINE = pathlib.Path(__file__).resolve().parents[1]
EXCLUS = ('/vendor/', '/node_modules/', '/storage/', '/.git/')


def depouille(texte):
    """Les CINQ syntaxes, systematiquement."""
    t = re.sub(r'\{\{--.*?--\}\}', ' ', texte, flags=re.S)
    t = re.sub(r'/\*.*?\*/', ' ', t, flags=re.S)
    t = re.sub(r'^\s*//.*$', ' ', t, flags=re.M)
    t = re.sub(r'^\s*#(?!\[).*$', ' ', t, flags=re.M)
    return t


def catalogue(nom, langue):
    p = RACINE / 'laravel' / 'lang' / langue / f'{nom}.php'
    if not p.exists():
        return None
    t = depouille(io.open(p, encoding='utf-8').read())
    return set(re.findall(r"^\s*['\"]([a-zA-Z0-9_.]+)['\"]\s*=>", t, re.M))


def population(nom):
    """Par CONTENU. Les catalogues eux-memes sont exclus : ils se citent."""
    out, lus = [], 0
    for p in sorted((RACINE / 'laravel').rglob('*')):
        if not p.is_file() or any(x in str(p) for x in EXCLUS):
            continue
        if p.suffix not in ('.php', '.js'):
            continue
        if p.parent.name in ('fr', 'en') and p.stem == nom:
            continue
        try:
            brut = io.open(p, encoding='utf-8', errors='ignore').read()
        except Exception:
            continue
        lus += 1
        if f'{nom}.' in brut:
            out.append((p, depouille(brut)))
    return out, lus


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    nom = sys.argv[1]
    domaines = {}
    for a in sys.argv[2:]:
        if a.startswith('--domaine'):
            val = a.split('=', 1)[1] if '=' in a else ''
            prefixe, _, valeurs = val.partition('=')
            domaines[prefixe] = [v for v in valeurs.split(',') if v]

    fr, en = catalogue(nom, 'fr'), catalogue(nom, 'en')
    if fr is None or en is None:
        print(f"  catalogue « {nom} » introuvable en fr ou en")
        return 2
    if fr != en:
        print(f"  ⛔ PARITE ROMPUE  fr\\en {sorted(fr - en)}  en\\fr {sorted(en - fr)}")

    pop, lus = population(nom)
    litterales, curatees, construits = set(), set(), []
    for p, t in pop:
        litterales |= set(re.findall(rf"['\"]{nom}\.([a-zA-Z0-9_]+)['\"]", t))
        for m in re.finditer(rf"['\"]({nom}\.[a-zA-Z0-9_]*)['\"]\s*\.", t):
            construits.append((str(p.relative_to(RACINE)), m.group(1)))
        for m in re.finditer(rf"foreach\s*\(\s*\[(.*?)\]\s*as\s*\$", t, re.S):
            if f"{nom}." in t[m.end():m.end() + 300]:
                curatees |= set(re.findall(r"'([a-zA-Z0-9_]+)'", m.group(1)))

    # les prefixes de concatenation NE SONT PAS des cles
    prefixes = {c.split('.', 1)[1] for _, c in construits}
    litterales -= prefixes

    print(f"  catalogue {nom}            {len(fr)} cles (fr = en)")
    print(f"  TEMOIN  fichiers lus       {lus}   (doit etre non nul)")
    print(f"  fichiers citant « {nom}. » {len(pop)}")
    print(f"  litterales                 {len(litterales)}")
    print(f"  liste curatee              {len(curatees)}")

    if construits and not domaines:
        print(f"\n  ⛔ {len(construits)} SITE(S) CONSTRUIT(S) — VERDICT REFUSE")
        for f, c in construits:
            print(f"     {f}  « {c} » + variable")
        print("\n  Enumerer chaque domaine A SA SOURCE, puis relancer :")
        for _, c in construits:
            print(f"     --domaine='{c}=valeur1,valeur2,…'")
        print("\n  *Une sonde qui devine un domaine rend un verdict faux dans les deux sens.*")
        return 3

    construites = set()
    for prefixe, valeurs in domaines.items():
        court = prefixe.split('.', 1)[1] if '.' in prefixe else prefixe
        construites |= {f'{court}{v}' for v in valeurs}

    atteintes = litterales | curatees | construites
    absentes = sorted(construites - fr) + sorted(curatees - fr)
    orphelines = sorted(fr - atteintes)

    print(f"  construites (domaines)     {len(construites)}")
    print(f"  ATTEINTES                  {len(atteintes & fr)} / {len(fr)}")

    if litterales and 'titre' in fr:
        print(f"  TEMOIN  « titre » atteint  {'oui' if 'titre' in atteintes else '⛔ NON'}")
    print(f"  TEMOIN  cle forgee atteinte {'⛔ OUI' if 'zzz_temoin_forge' in atteintes else 'non'}")

    if absentes:
        print(f"\n  ⛔ CLES ATTEINTES MAIS ABSENTES DU CATALOGUE : {len(absentes)}")
        for k in absentes:
            print(f"     {nom}.{k}   -> `__()` afficherait « {nom}.{k} » a l'utilisateur")
    else:
        print("\n  ✅ aucune cle atteinte n'est absente du catalogue")

    print(f"\n  cles ORPHELINES : {len(orphelines)}")
    for k in orphelines:
        print(f"     {nom}.{k}")

    return 2 if absentes else 0


if __name__ == '__main__':
    sys.exit(main())
