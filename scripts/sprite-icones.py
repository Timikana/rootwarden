"""Construit laravel/public/icones/lucide.svg, un sprite limite aux icones employees.

Source : le paquet npm `lucide-static` (licence ISC), telecharge et extrait a part :
    npm pack lucide-static@<version> && tar xzf lucide-static-<version>.tgz
Usage, depuis la racine du depot :
    python3 -I scripts/sprite-icones.py <chemin>/package
Ajouter une icone : l'ecrire dans ICONES, relancer, committer le sprite.
"""
import json, re, sys, pathlib

ICONES = sorted(set("""
layout-dashboard key-round users key shield-check folder-lock refresh-cw server-cog activity
terminal container scroll-text bug clipboard-check git-compare brick-wall ban scan-search radar
user-cog users-round badge-check wrench list-checks database-backup file-clock square-terminal
search message-square circle-user book-open plug bell moon sun chevron-right info triangle-alert coffee
""".split()))

paquet = pathlib.Path(sys.argv[1])
version = json.loads((paquet / 'package.json').read_text())['version']
racine = pathlib.Path(__file__).resolve().parent.parent
sortie = racine / 'laravel/public/icones'
sortie.mkdir(parents=True, exist_ok=True)

symboles = []
for nom in ICONES:
    svg = (paquet / 'icons' / f'{nom}.svg').read_text()
    corps = re.search(r'<svg[^>]*>(.*)</svg>', svg, re.S).group(1)
    corps = re.sub(r'<!--.*?-->', '', corps, flags=re.S)
    corps = ' '.join(l.strip() for l in corps.strip().splitlines())
    symboles.append(f'<symbol id="i-{nom}" viewBox="0 0 24 24">{corps}</symbol>')

(sortie / 'lucide.svg').write_text(
    f'<!-- Lucide v{version} (ISC, https://lucide.dev), sous-ensemble genere par scripts/sprite-icones.py -->\n'
    '<svg xmlns="http://www.w3.org/2000/svg">\n' + '\n'.join(symboles) + '\n</svg>\n')
(sortie / 'LICENSE-lucide.txt').write_text((paquet / 'LICENSE').read_text())
print(f'{len(symboles)} icones, Lucide v{version}')
