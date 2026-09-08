# DOSSIER-61 — Le chemin qui accorde le root existe en deux exemplaires

**Mesuré le 2026-09-09 entre 00:50 et 01:20 CEST.** Aucun geste exercé sur
aucune machine. Tout ce qui suit vient de lectures de l'arbre et de mesures
locales en python.

> Ce dossier sort d'un travail qui ne le cherchait pas : annoter les 106
> interpolations de commande root du dépôt. **Ce qui se trouve en justifiant,
> on ne le trouve pas en relisant** — c'est la troisième source, distincte de
> l'écriture et de la revue.

---

## 1. Le fait

`backend/routes/ssh.py` porte **deux fois les mêmes neuf commandes root**.

```
deploy_platform_key()      :813    ->  bloc :927-:960    NOPASSWD a :951
deploy_service_account()   :1346   ->  bloc :1406-:1439  NOPASSWD a :1430
```

⚠ *Numéros relevés le 2026-09-09 à 01:30 CEST, **après** la pose des
annotations — qui ont décalé le fichier de 76 lignes. Les numéros d'avant
(`:792` / `:1295`) circulent dans le message de commit `e9236d41` et dans les
commentaires du fichier : ils désignent les mêmes blocs, dans l'état d'avant.*

`diff` après normalisation de l'indentation : **les seuls écarts sont des
commentaires et deux noms de variables**. Les neuf gestes exécutés sont
identiques, dans le même ordre :

```
1  useradd -r -m -s /bin/bash rootwarden      (si absent)
2  chown rootwarden:rootwarden /home/rootwarden
3  mkdir -p  /home/rootwarden/.ssh
4  chmod 700 /home/rootwarden/.ssh
5  (depot de la cle publique)
6  chmod 600 /home/rootwarden/.ssh/authorized_keys
7  chown -R rootwarden:rootwarden /home/rootwarden/.ssh
8  echo 'rootwarden ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/rootwarden
9  visudo -cf /etc/sudoers.d/rootwarden
```

**L'étape 8 accorde le sudo sans mot de passe, total, sur la machine cible.**
C'est le geste le plus puissant du produit, et il est écrit deux fois.

---

## 2. Pourquoi ça compte, et ce que ça n'est pas

**Ce n'est pas un défaut de sécurité aujourd'hui.** Les deux blocs sont
corrects, et les deux routes portent `@require_machine_access`. Rien n'est
ouvert.

**C'est un défaut de RÉPARABILITÉ.** La forme est exactement celle de V7 :

> V7 avait corrigé le CHEMIN et pas l'ADRESSE. Le défaut est revenu par
> l'autre porte, et il est revenu parce que personne ne savait qu'il y avait
> une autre porte.

Un correctif futur sur l'un des deux blocs — durcir les permissions, restreindre
le `NOPASSWD`, ajouter une vérification — **laisse l'autre armé**, et rien dans
le code ne le signale. *Les deux blocs sont à 450 lignes l'un de l'autre, dans
deux fonctions dont les noms ne se ressemblent pas.*

⚠ **Et l'écart existe déjà, mesuré et non supposé.** Le piège `sshd AllowUsers`
— serveurs durcis où l'authentification `rootwarden` casse *après* le
déploiement, *« cas observé en prod sur serveurs hardenés »* dit le commentaire —
est rattrapé par le helper `_ensure_sshd_allows_user`. **Il n'est appelé que
depuis un des deux jumeaux :**

```
_ensure_sshd_allows_user  appelee depuis
  :984    deploy_platform_key      (:813)
  :2296   sshd_allow_user          (:2247)     <- une troisieme route, dediee
  ————    deploy_service_account   (:1346)     <- ZERO appel
```

*Je l'avais écrit avant de le mesurer, et je l'ai mesuré avant de le publier :
le compte est bien 1 appel contre 0, dérivé par balayage des `def` du fichier
et non lu à l'œil.* **`deploy_service_account` peut donc rendre une machine
durcie injoignable là où son jumeau se rattrape.**

---

## 3. Ce que je NE fais pas, et pourquoi

**Je n'unifie pas les deux blocs.** Le geste est nommé dans les interdits
permanents — *« ssh le déploiement K4 »* — et il ne s'agit pas d'une formalité :

```
ce qu'une unification touche      ce que ca risque
────────────────────────────────  ──────────────────────────────────────
l'ordre des neuf commandes        un chown avant un mkdir casse le depot
la gestion des codes de retour    un echec silencieux laisse la machine
                                    a moitie configuree, sans sudo et sans
                                    cle : elle devient injoignable par le
                                    produit ET par le compte de service
les deux appelants                deux routes vivantes, dont une (K4) est
                                    le deploiement de cle plateforme
```

**Et le service ne recharge pas le code de l'arbre** (`use_reloader = False`,
`workers = 4`). Une unification écrite aujourd'hui ne serait éprouvable qu'après
un redémarrage qui appartient à l'exploitant. *Écrire un refactor de ce chemin
sans pouvoir l'exercer, c'est produire du code non mesuré sur le geste le plus
dangereux du produit.*

---

## 4. Ce que je consigne, et ce que ça vaut en attendant

Les deux blocs portent désormais **une annotation qui les relie**. Celle du
second dit, dans le fichier :

> *⚠ ET CE BLOC EST LE JUMEAU DE :892-:908. […] Un correctif sur l'un des deux
> chemins laisse l'autre armé : c'est la forme exacte du défaut V7, où le CHEMIN
> avait été corrigé et pas l'ADRESSE.*

**Ce n'est pas une correction, et je ne la présente pas comme telle.** C'est un
panneau à l'endroit exact où quelqu'un passera. *Il vaut ce que vaut un panneau :
il ne tient que si on le lit.* La garde par construction — un seul helper appelé
deux fois — reste à faire, et elle appartient à l'exploitant.

---

## 5. Ce qui revient à l'exploitant

**① Trancher l'unification.** Trois options, par coût croissant :

```
a  ne rien faire            le panneau tient tant qu'on le lit
b  extraire un helper       ~30 lignes deplacees, DEUX routes a re-eprouver
                            sur la machine 3 (OpenCVE-Test-OnPrem, 192.168.0.2)
c  b + porter le rattrapage AllowUsers au jumeau, qui ne l'a pas
```

**Ma recommandation est (c), après un redémarrage, éprouvée sur la 3.** L'écart
`AllowUsers` n'est pas théorique : le commentaire du code dit qu'il a été
*observé en production*. Le jumeau peut donc rendre une machine durcie
injoignable, et c'est un défaut vivant, pas une dette de forme.

**② La portée du `NOPASSWD: ALL`.** L'étape 8 accorde tout, à un compte de
service, sans mot de passe. C'est le dessin du produit et je ne le remets pas en
cause ici — mais c'est une **question de portée de droit**, distincte de
l'injection, et les annotations que je viens de poser le disent explicitement
pour qu'on ne les lise pas comme un blanc-seing.

---

## 6. En marge : la classe est fermée

Le travail qui a produit ce dossier a un résultat propre.

```
cliquet semgrep   106 -> 104 -> 99 -> 94 -> 89 -> 80 -> 71 -> 44 -> 1 -> 0
```

**Les 106 interpolations de commande root du dépôt portent chacune une
justification qui nomme son mécanisme** — alphabet, rejet, dérivation, origine
littérale, échappement, calcul serveur — et son site. Aucune ne dit « c'est sûr ».

**À zéro, le cliquet change de nature** : il ne mesure plus une dette qui
descend, il **refuse** la première interpolation non justifiée qui reparaîtra.
*Une porte qui refuse toujours, on cesse de la regarder ; une porte qui n'a
jamais refusé et qui refuse aujourd'hui, on la lit.*

⚠ **Et la limite, qui reste ouverte et documentée** : la règle ne voit que la
f-string **en ligne** dans l'appel. Une f-string affectée à une variable d'abord
lui échappe — **cinq sites dans `routes/updates.py` seul**, dont `:596`, qui
porte la valeur exacte de la vulnérabilité corrigée cette semaine. *Zéro
trouvaille ne veut pas dire zéro site : ça veut dire zéro site VISIBLE par cet
instrument.* Étendre la règle demande un juge semgrep local — la tentative en
aveugle par la CI a fait sortir semgrep en code 7 sans sortie, et a emporté les
deux jobs de règles custom.
