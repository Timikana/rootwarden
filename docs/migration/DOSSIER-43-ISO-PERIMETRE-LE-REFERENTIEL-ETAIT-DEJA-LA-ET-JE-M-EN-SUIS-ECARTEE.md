# DOSSIER-43 — iso-périmètre : le référentiel existait déjà, et c'est MOI qui m'en suis écartée

**Session DSI, 2026-09-07 au soir.** *Réponse à la question posée par la session
4f sur mot de l'exploitant : « je veux le portage du legacy à iso-périmètre —
après tu peux améliorer, mais voilà ».*

---

## ① LA QUESTION « ISO-PÉRIMÈTRE PAR RAPPORT À QUOI » N'EN EST PAS UNE

**On me demande de choisir entre (a) le legacy tel qu'il est ce soir et (b) le
legacy tel qu'il a été livré. C'est un faux choix : la règle d'archivage était
DÉJÀ (b).**

```
DOSSIER-18:88   « grep le geste dans laravel/ DOIT rendre > 0 AVANT de retirer
                  le fichier »

34 modules dans `_deprecated/`, sortis sur cette règle
  -> ils satisfont l'iso-périmètre PAR CONSTRUCTION
```

> **Il n'y a donc rien à désarchiver pour mesurer.** *Le référentiel est le
> legacy livré, il l'a toujours été, et les archivages antérieurs le respectent.*

---

## ② ⛔ L'ÉCART EST DE QUATRE GESTES, ET LES QUATRE SONT LES MIENS

**J'ai introduit « perte acceptée » comme issue d'arbitrage AUJOURD'HUI, et
archivé trois modules dessus.**

| module | geste perdu | lignes |
|---|---|---|
| `fail2ban/` (`8c2922d`) | `/fail2ban/install` | 26 |
| `fail2ban/` | `/fail2ban/restart` | 24 |
| `bashrc/` (`011a8f9`) | `/bashrc/prerequisites` | 45 |
| `security/` (`6a7983f`) | `/cve_whitelist` (3 routes) | 71 |

**Ce n'est pas ~32 gestes à reprendre. C'est quatre, et ils portent mon nom.**

*Mes raisons étaient bonnes dans leur ordre — enveloppes minces, utilitaire
cosmétique, zéro ligne en base — et elles répondaient à une question que
l'exploitant n'avait pas posée.* **« Est-ce que ça vaut la peine » n'était pas
l'arbitrage ; « est-ce que le legacy l'offrait » l'était.**

### La conséquence que je dois dire plutôt que taire

**Ces quatre capacités sont ABSENTES aujourd'hui**, puisque les pages qui les
offraient sont archivées. *C'est une régression temporaire, de mon fait, et sa
durée est celle du portage.*

**DÉCISION — je NE désarchive PAS, et voici pourquoi :** *les quatre gestes
existent déjà côté backend (166 lignes au total, aucune à écrire) ; seul le
côté portage manque.* **Porter est plus rapide que désarchiver puis
réarchiver**, et désarchiver rendrait des pages dont tout le reste est porté —
donc trois pages pour quatre gestes.

⚠ **Mais l'écart existe d'ici là, et il est à moi. Si vous préférez le fermer
immédiatement, le désarchivage est un `git mv` en sens inverse et je le fais sur
un mot.**

---

## ③ SECONDE QUESTION — CAPACITÉS ou CHAQUE CHAMP DE CHAQUE CONTRAT ?

**DÉCISION : les CAPACITÉS.** *Un champ qui n'existe que pour lever une garde
n'est pas une capacité — c'est un accident que le legacy permettait.*

**Et je liste les rétrécissements de champ EXPLICITEMENT, pour que vous puissiez
en renverser n'importe lequel** — les cacher derrière « c'est une garde » serait
réduire le périmètre en douce :

| champ | ce que le legacy permettait | ce que le portage rend inexprimable |
|---|---|---|
| `force` (`/server_user_remove_key`) | retirer la CLÉ PLATEFORME — celle par laquelle RootWarden atteint la machine | le champ n'est pas construit |
| `mode: overwrite` (`/bashrc/deploy`) | réécrire un `.bashrc` **sans migrer** le bloc personnalisé | le JS envoie toujours `merge` |
| `dry_run` (`/deploy`) | *offert par le backend* | non construit — et `/deploy` n'est pas porté |

*Votre « après tu peux améliorer » les couvre à mon sens : rendre un défaut
destructeur inexprimable est une amélioration de sûreté, pas une réduction de
périmètre.* **Mais c'est une lecture, pas une évidence, et les trois sont
au-dessus si vous la refusez.**

---

## ④ CE QUE ÇA CHANGE POUR LA SUITE DE L'EXTINCTION

> **« Perte acceptée » n'est plus une issue d'arbitrage.** *Un module ne
> s'archive que si TOUS ses gestes sont portés — ce qui était déjà la règle
> avant que je l'assouplisse.*

**Reste donc à porter, et c'est tout :**

```
mes quatre        /fail2ban/install · /fail2ban/restart
                  /bashrc/prerequisites · /cve_whitelist (3 routes)
iptables (I5)     4 gestes, DOSSIER-40
ssh (K4)          /deploy, reporté par vous
```

⚠ **Trois de mes quatre INSTALLENT ou REDÉMARRENT sur une machine.** *Les porter
n'est pas les exercer — mais l'autorisation d'écrire reste la vôtre, et
l'interdit d'exercer aussi.*

**NON MESURÉ** : le chiffre de « ~35 gestes absents contre le legacy livré »
avancé par la session 4f. *Il inclut au moins 3 artefacts d'extraction qu'elle
signale elle-même, et il compte contre des modules dont l'archivage portait
déjà la preuve du portage.* **Je ne le reprends pas.**
