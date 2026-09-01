"""
jointure.py - LA JOINTURE : quel appelant du portage consomme quelle route du
backend, et cette route peut-elle rendre `200` avec `success: false` ?

QA-011, seconde moitie. Ce n'est PAS un test : c'est un outil d'audit, et son
resultat vit dans `docs/migration/QA-APPELANTS.md`. Ce qui est TESTE, c'est la
famille des routes (`backend/tests/test_verdicts_deux_cents.py`) et le releve des
appelants (`laravel/tests/Feature/AppelantsDuBackendTest.php`).

TROIS LANGAGES, TROIS ANALYSEURS — AUCUNE EXPRESSION REGULIERE SUR DU CODE
--------------------------------------------------------------------------
    JavaScript  `analyse-appelants.mjs`  (acorn)      -> les sites d'appel
    PHP         `extrait-urls.php`       (token_get_all) -> `cle` -> chemin
    Python      ce fichier               (ast)        -> la famille de la route

Le premier croisement avait ete fait au `grep` du chemin litteral dans le
JavaScript. Il rendait « AUCUN appelant » pour CINQ routes, et DEUX ont ete
resolues en une commande sur la couche PHP : `supervision.js` n'ecrit jamais
`/supervision/zabbix/version`, il lit `url_version`, fabrique par
`SupervisionController.php`. **Un motif qui ne lit qu'un langage sur trois se
trompe dans le sens qui rassure.**

CE QUE CET OUTIL PRODUIT : DES CANDIDATS, JAMAIS DES VERDICTS
-------------------------------------------------------------
Il a signale `mises-a-jour.js:63 -> /linux_version` comme « a risque ». Lecture
faite : `releve()` teste `res.corps.success === false` a la ligne 274, dans le
bon ordre. **Faux positif** — la regle comptait `delegue` comme un risque, alors
que `delegue` veut precisement dire « un appelant du fichier lit le verdict ».
Troisieme fausse accusation dans le developpement de cet outil, et la troisieme
rattrapee en LISANT le code signale.

LES SILENCES, ET IL Y EN A DEUX SORTES
---------------------------------------
    silence MESURE        la cle PHP existe mais son URL est INTERPOLEE
                          (`url("/api/gateway/supervision/{$plateforme}/version")`)
    silence par INCAPACITE la cible est une variable qu'on ne remonte pas

**Un silence mesure et un silence par incapacite ne se ressemblent que dans un
tableau.** Ils sont comptes separement, et la couverture est annoncee.
"""
import json, ast, pathlib, re, sys
S = sys.argv[1]
carte = json.load(open(S + '/map.json'))
appels = json.load(open(S + '/appels.json'))['detail']

vers_passerelle = {e['cle']: e['cible'].replace('/api/gateway', '', 1)
                   for e in carte['resolues'] if e['cible'].startswith('/api/gateway/')}
interpolees = {e['cle'] for e in carte['interpolees']}

R = pathlib.Path('backend/routes')
def nom(d):
    c = d.func if isinstance(d, ast.Call) else d
    return getattr(c, 'attr', getattr(c, 'id', ''))

familles = {}
for f in sorted(R.glob('*.py')):
    a = ast.parse(f.read_text(encoding='utf-8'))
    for fn in ast.walk(a):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        ch = None
        for d in fn.decorator_list:
            if isinstance(d, ast.Call) and nom(d) == 'route' and d.args and isinstance(d.args[0], ast.Constant):
                ch = d.args[0].value
        if ch is None:
            continue
        cond = dur = False
        for r in ast.walk(fn):
            if not isinstance(r, ast.Return) or r.value is None:
                continue
            v, st = r.value, 200
            if isinstance(v, ast.Tuple) and len(v.elts) >= 2:
                s = v.elts[1]
                st = s.value if isinstance(s, ast.Constant) else '?'
                v = v.elts[0]
            if st != 200 or not (isinstance(v, ast.Call) and nom(v) == 'jsonify'):
                continue
            d0 = ({k.value: val for k, val in zip(v.args[0].keys, v.args[0].values)
                   if isinstance(k, ast.Constant)}
                  if (v.args and isinstance(v.args[0], ast.Dict)) else {})
            s = d0.get('success')
            if s is None:
                continue
            if isinstance(s, ast.Constant):
                if s.value is False:
                    dur = True
            else:
                cond = True
        familles[ch] = 'dur' if dur else ('conditionnel' if cond else 'jamais')

# Le gabarit interpole d'une cle PHP : `/api/gateway/supervision/{$plateforme}/version`
gabarits = {e['cle']: e['cible'].replace('/api/gateway', '', 1)
            for e in carte['interpolees'] if e['cible'].startswith('/api/gateway/')}


def motif(chemin):
    """Rend le chemin avec ses segments VARIABLES neutralises.

    `/supervision/{$plateforme}/version` cote PHP et `/supervision/<platform>/version`
    cote Flask decrivent le MEME ensemble de chemins. Les comparer segment a
    segment, en traitant les deux formes de variable comme un joker, est un
    appariement de FORME — pas une supposition sur la valeur.
    """
    return tuple('*' if (seg.startswith('{') or seg.startswith('<')) else seg
                 for seg in chemin.split('/'))


def route_du_gabarit(gabarit):
    """La route du backend qui accepte ce gabarit — s'il n'y en a QU'UNE.

    Plusieurs correspondances veut dire que le gabarit ne designe pas une route
    mais une famille : on ne tranche pas, on le dit.
    """
    cible = motif(gabarit)
    candidates = [k for k in familles if motif(k) == cible]
    return candidates[0] if len(candidates) == 1 else None


def resout(cible, origine=None):
    m = re.match(r"^PASSERELLE \+ '(/[^']+)'$", cible)
    if m:
        return m.group(1), 'resolu'
    m = re.match(r"^'/api/gateway(/[^']+)'$", cible)
    if m:
        return m.group(1), 'resolu'
    m = re.match(r'^(?:L|libelles|S)\.([a-z_0-9]+)', cible)
    if m:
        c = m.group(1)
        if c in vers_passerelle:
            return vers_passerelle[c], 'resolu'
        if c in interpolees:
            return None, 'silence MESURE : cle PHP interpolee'
        return None, 'silence MESURE : cle absente de la carte PHP'

    # ══ CE QUE LA CIBLE EST VRAIMENT, QUAND ELLE N'EST PAS LITTERALE SUR PLACE
    #
    # Dix des treize « silences par incapacite » n'en etaient pas : la cible
    # etait une constante du fichier, ou une cle passee a un helper local.
    # L'analyseur JS les nomme maintenant (`origine`), et les deux formes se
    # resolvent ici. *Compter comme de l'ignorance ce qu'on n'a pas regarde
    # melange deux choses qui ne se ressemblent que dans un tableau.*
    if origine:
        forme = origine.get('forme')
        if forme in ('litteral', 'constante'):
            chemin = origine['valeur']
            if chemin.startswith('/api/gateway/'):
                return chemin.replace('/api/gateway', '', 1), 'resolu'
            # Chemin du PORTAGE lui-meme, pas de la passerelle. Ce n'est PAS un
            # silence : la cible est entierement connue. Ce que cette mesure ne
            # dit pas, c'est si le controleur Laravel derriere relaie vers le
            # backend — question de la couche PHP, et elle est nommee.
            return None, f'PORTAGE : {chemin}'
        if forme == 'cle_indirecte':
            cle = origine['cle']
            if cle in vers_passerelle:
                return vers_passerelle[cle], 'resolu'
            if cle in gabarits:
                route = route_du_gabarit(gabarits[cle])
                if route:
                    return route, 'resolu'
                return None, f'silence MESURE : gabarit {gabarits[cle]}'
            return None, f"silence MESURE : cle indirecte '{cle}' absente de la carte PHP"

    return None, 'silence PAR INCAPACITE : cible variable'

def famille_de(ch):
    for c in (ch, ch.rstrip('/'), ch.split('?')[0], ch.split('?')[0].rstrip('/')):
        if c in familles:
            return familles[c]
    # espace de noms : `/bashrc/users?machine_id=` -> chercher un prefixe
    for k, v in familles.items():
        if ch.split('?')[0].rstrip('/') == k.rstrip('/'):
            return v
    return '(route inconnue)'

lignes, risque, silences = [], [], []
compte = {'resolu': 0, 'remonte': 0, 'portage': 0, 'mesure': 0, 'incapacite': 0}
for a in appels:
    ch, cause = resout(a['cible'], a.get('origine'))
    cibles = []
    if ch:
        compte['resolu'] += 1
        cibles = [(ch, 'directe')]
    elif a.get('chemins_appelants'):
        compte['remonte'] += 1
        cibles = [(c, 'remontee') for c in a['chemins_appelants']]
    elif cause.startswith('PORTAGE'):
        compte['portage'] += 1
        silences.append((f"{a['fichier']}:{a['ligne']}", cause))
    else:
        compte['mesure' if 'MESURE' in cause else 'incapacite'] += 1
        silences.append((f"{a['fichier']}:{a['ligne']}", cause))

    for c, voie in cibles:
        fam = famille_de(c)
        lignes.append((f"{a['fichier']}:{a['ligne']}", a['verdict'], c, fam, voie))
        if fam in ('dur', 'conditionnel') and a['verdict'] in ('ignore', 'delegue_sans_lecteur'):
            risque.append((f"{a['fichier']}:{a['ligne']}", a['verdict'], c, fam))

interessantes = [l for l in lignes if l[3] in ('dur', 'conditionnel', '(route inconnue)')]
for l in sorted(interessantes):
    print(f'{l[0]:32} {l[1]:12} {l[2]:36} {l[3]:16} {l[4]}')
print()
couverts = compte['resolu'] + compte['remonte']
# `portage` sort du DENOMINATEUR : ces sites ne visent pas la passerelle, donc la
# question « cette route peut-elle rendre 200 en mentant ? » ne se leur pose pas.
# Les compter comme non couverts ferait baisser une couverture qui n'a rien a
# couvrir la — et les compter comme couverts la ferait monter sans mesure.
interrogeables = len(appels) - compte['portage']
print(f"sites resolus DIRECTEMENT {compte['resolu']} | par REMONTEE {compte['remonte']} | "
      f"silences MESURES {compte['mesure']} | par INCAPACITE {compte['incapacite']} | "
      f"hors passerelle (PORTAGE) {compte['portage']} | total {len(appels)}")
print(f"couverture : {100*couverts//interrogeables} %  ({couverts}/{interrogeables} sites "
      f"interrogeables, {len(lignes)} chemins)")
print()
print('== CE QUI RESTE NON RESOLU, ET POURQUOI ==')
for site, cause in sorted(set(silences)):
    print(f'   {site:32} {cause}')
print()
print('== A RISQUE : route de la famille 200-menteuse, appelant qui ne VERIFIE pas ==')
for r in sorted(set(risque)):
    print('   ', r)
print('   (aucun)' if not risque else '')

