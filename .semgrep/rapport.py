#!/usr/bin/env python3
"""Rapport lisible d'un `semgrep --json`, pour la CI et pour la main.

POURQUOI CE FICHIER EXISTE PLUTOT QU'UN `python3 -c` DANS LE YAML.
Trois fois de suite (2026-09-08) j'ai ecrit un bloc python multi-ligne a
l'interieur d'un scalaire `run: |` de GitHub Actions. L'indentation d'un
scalaire est fixee par sa PREMIERE ligne : toute ligne moins indentee TERMINE
le bloc. Un bloc python colle a gauche casse donc le YAML — silencieusement a
l'ecriture, bruyamment a l'execution.

**Un fichier n'a pas d'indentation heritee, et il se teste.** `py_compile` le
verifie, et on peut le lancer sur un JSON forge sans passer par la CI.

Deux sorties, et l'ordre est STABLE dans les deux : un tri instable ferait lire
une regression dans un simple reordonnancement.
  --par-regle    combien de trouvailles par regle
  --par-fichier  le fichier et la ligne de chacune
"""

import collections
import json
import sys


def charge(chemin):
    with open(chemin, encoding="utf-8") as f:
        return json.load(f)


def par_regle(d):
    c = collections.Counter(
        r["check_id"].split(".")[-1] for r in d.get("results", [])
    )
    # tri par compte DECROISSANT puis par nom : deux regles a egalite ne
    # doivent pas permuter d'un run a l'autre.
    for regle, n in sorted(c.items(), key=lambda t: (-t[1], t[0])):
        print(f"  {n:>4}  {regle}")
    return sum(c.values())


def par_fichier(d):
    par = collections.defaultdict(list)
    for r in d.get("results", []):
        par[r["path"]].append(
            (r["start"]["line"], r["check_id"].split(".")[-1])
        )
    for chemin in sorted(par):
        print(f"  {chemin}  ({len(par[chemin])})")
        for ligne, regle in sorted(par[chemin]):
            print(f"      :{ligne:<6} {regle}")
    return sum(len(v) for v in par.values())


def main(argv):
    if len(argv) < 2:
        print("usage: rapport.py <semgrep.json> [--par-regle|--par-fichier]",
              file=sys.stderr)
        return 2
    d = charge(argv[1])
    mode = argv[2] if len(argv) > 2 else "--par-regle"
    if mode == "--par-fichier":
        n = par_fichier(d)
    else:
        n = par_regle(d)
    # Le TOTAL est imprime par l'appelant, qui le compare a la reference. Ici
    # on le rend sur la sortie d'erreur pour qu'il n'entre pas dans le rapport
    # tout en restant verifiable.
    print(f"total : {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
