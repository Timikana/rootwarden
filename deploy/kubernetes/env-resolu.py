"""Resout un fichier d'environnement Docker Compose en paires CLE=valeur brutes.

    python3 -I env-resolu.py srv-docker.env > env-resolu

Compose interpole `${VAR}` dans un `env_file` ; `kubectl create secret
--from-env-file` ne le fait pas : `MYSQL_DATABASE=${DB_NAME}` y arriverait tel
quel. On resout donc ici, avec les memes sources que Compose : les autres
variables du fichier, puis l'environnement du shell. Une variable inconnue vaut
la chaine vide (Compose avertit et fait de meme) ; on le dit sur stderr.

Gere `${VAR}`, `${VAR:-defaut}`, `$VAR`, les guillemets englobants et `$$`.
"""
import re
import sys
import os

MOTIF = re.compile(r'\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)')


def lit(chemin):
    brut = {}
    for n, ligne in enumerate(open(chemin, encoding='utf-8'), 1):
        s = ligne.strip()
        if not s or s.startswith('#'):
            continue
        if s.startswith('export '):
            s = s[7:].lstrip()
        if '=' not in s:
            sys.exit(f"{chemin}:{n} : ligne sans '=' : {s[:40]!r}")
        cle, val = s.split('=', 1)
        cle = cle.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', cle):
            sys.exit(f"{chemin}:{n} : nom de variable invalide : {cle!r}")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in '"\'':
            val = val[1:-1]
        elif ' #' in val:
            val = val.split(' #', 1)[0].rstrip()
        brut[cle] = val
    return brut


def resout(brut):
    inconnues = set()

    def valeur(nom, pile):
        if nom in pile:
            sys.exit(f"reference circulaire : {' -> '.join(pile + [nom])}")
        if nom in brut:
            return remplace(brut[nom], pile + [nom])
        if nom in os.environ:
            return os.environ[nom]
        return None

    def remplace(texte, pile):
        def un(m):
            if m.group(0) == '$$':
                return '$'
            nom = m.group(1) or m.group(3)
            v = valeur(nom, pile)
            if v is None or (v == '' and m.group(2) is not None):
                if m.group(2) is not None:
                    return m.group(2)
                inconnues.add(nom)
                return ''
            return v
        return MOTIF.sub(un, texte)

    sortie = {cle: remplace(val, [cle]) for cle, val in brut.items()}
    for nom in sorted(inconnues):
        print(f"[env] variable inconnue, remplacee par une chaine vide : {nom}", file=sys.stderr)
    return sortie


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("usage : env-resolu.py <fichier.env>")
    for cle, val in resout(lit(sys.argv[1])).items():
        if '\n' in val:
            sys.exit(f"{cle} : valeur sur plusieurs lignes, non representable")
        print(f"{cle}={val}")
