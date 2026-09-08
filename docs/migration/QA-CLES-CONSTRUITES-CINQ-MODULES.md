# Les clés i18n CONSTRUITES des cinq modules — couverture par la SOURCE

**Mesuré le 2026-09-08 entre 04:43 et 04:58 CEST**, en lecture d'arbre. Aucun geste,
aucune requête sur une machine.

> ## Verdict : **couverture COMPLÈTE — zéro clé manquante en `fr` comme en `en`.**
> Une absence apparente (`fail2ban.etat_actif_aide`) est **correcte par
> construction** : la vue ne la demande jamais. Et elle est le seul endroit où la
> complétude repose sur une **condition** plutôt que sur la source.

---

## 1. La population est de TREIZE sites, pas cinq

| module | sites de clé construite |
|---|---|
| `sftp` | `acces-sftp.blade.php:112` `f_` · `:118` `h_` · `:207` `etat_` · `AccesSftpController:64` |
| `fail2ban` | `fail2ban.blade.php:193` `etat_` · `:196` `etat_…_aide` · `Fail2banController:161` |
| `politiques` | `politiques.blade.php:69` `preset_` · `:199` `etat_` · `PolitiquesController:63` `aide_` · `:73` |
| `serveurs` | `serveurs.blade.php:382` `cycle_` · `ServeursController:251` `cycle_…_fait` |
| **`bashrc`** | **AUCUN** — c'est le seul des cinq sans clé construite |

**Les huit sites non repérés au premier tour le sont pour les deux raisons déjà
nommées** : `sftp` n'a ni vue ni JS à son nom (ses clés vivent dans
`acces-sftp.*` et `AccesSftpController`), et cinq des huit sont **côté contrôleur**,
dans des listes curatées.

⚠ **Et un artefact de MA sonde, corrigé avant publication.** Mon premier relevé
donnait `politiques:176`, `fail2ban:126`, `serveurs:327` — **faux**. Mon dépouillement
des commentaires **supprimait les lignes**, ce qui décale tout ce qui suit. Corrigé en
remplaçant chaque ligne de commentaire par une ligne **vide**. *Les numéros d'origine
étaient les bons ; les miens étaient les décalés.*

---

## 2. Les sources énumérées, et d'où elles viennent

| famille | valeurs | **source** |
|---|---|---|
| `politiques.preset_*` · `politiques.aide_*` | `all_nopasswd` `restart_services` `apt_only` `read_logs` `systemctl_specific` `custom` | **constante PHP** `Services\Politiques::PREREGLAGES:82-89` |
| `politiques.etat_*` · `sftp.etat_*` | `applied` `rolled_back` `failed` `superseded` | **enum en base** `policy_deployments.status` |
| `serveurs.cycle_*` · `cycle_*_fait` | `active` `retiring` `archived` | **enum en base** `machines.lifecycle_status` |
| `fail2ban.etat_*` | `absent` `arrete` `actif` | ⚠ **calculé DANS LA VUE** (`fail2ban.blade.php:187`) — pas une source de données |
| `sftp.f_*` · `sftp.h_*` | `sftp_only` `password` `tcp` `agent` `x11` | ⚠ **défini DANS LA VUE** (`acces-sftp.blade.php:12-18`) |
| 3 listes curatées | 13 · 130 · 18 clés | `AccesSftpController:57` · `Fail2banController:75` · `PolitiquesController:65` |

**Deux des six sources ne sont ni un enum ni une constante de service : elles sont
écrites dans la vue elle-même.** *Aucune migration de base ne les fera bouger, et
aucune revue de schéma ne les verra.*

---

## 3. La couverture, famille par famille

    politiques.preset_*      fr 6/6   en 6/6
    politiques.aide_*        fr 6/6   en 6/6
    politiques.etat_*        fr 4/4   en 4/4
    sftp.etat_*              fr 4/4   en 4/4
    sftp.f_*                 fr 5/5   en 5/5
    sftp.h_*                 fr 5/5   en 5/5
    serveurs.cycle_*         fr 3/3   en 3/3
    serveurs.cycle_*_fait    fr 3/3   en 3/3
    fail2ban.etat_*          fr 3/3   en 3/3
    fail2ban.etat_*_aide     fr 2/3   en 2/3   <- voir §4
    listes curatees          sftp 13  fail2ban 130  politiques 18   toutes OK

    TEMOIN qui DOIT rendre non-zero : 3 cles inventees -> 3 absentes ✓

---

## 4. La seule absence, et pourquoi ce n'est PAS un défaut

`fail2ban.etat_actif_aide` n'existe ni en `fr` ni en `en`. **Elle n'est jamais
demandée** :

    fail2ban.blade.php:195   @if ($etat !== 'actif')
    fail2ban.blade.php:196       {{ __('fail2ban.etat_' . $etat . '_aide') }}

*Un état actif n'a pas besoin d'explication ; les deux autres si.* La famille est donc
bornée à **deux** valeurs, et elle est complète.

> ⚠ **Mais la complétude repose ici sur une CONDITION DE VUE, pas sur la source.**
> Les neuf autres familles sont complètes parce que leur source est énumérable et
> qu'on a couvert chaque valeur. Celle-ci l'est parce qu'une garde retire un cas.
> **Retirer le `@if` — ou changer sa condition — rend la clé nécessaire, et `__()`
> affichera `fail2ban.etat_actif_aide` à l'utilisateur.**

C'est le seul point des cinq modules où la couverture est **fragile plutôt
qu'établie**, et c'est le seul qui mérite d'être noté quelque part.

---

## 5. Ce que je n'ai pas fait

- **je n'ai écrit aucune épreuve** : mon mandat exclut le code, tests compris. La
  forme que vous proposez (une épreuve qui asserte la couverture famille par famille)
  est la bonne, et il faut qu'elle lise les sources — l'enum, la constante, **et les
  deux tableaux définis dans les vues** — sans quoi elle sera fausse dès qu'une valeur
  s'ajoutera ;
- je n'ai pas vérifié les **68 autres sites de clé construite** du portage : il y en a
  **81 au total**, hors des cinq modules demandés ;
- je n'ai pas mesuré si chaque clé du CATALOGUE a un consommateur — c'est la question
  inverse, et vos comptes de « clé que rien n'appelle » restent à refaire en balayant
  les contrôleurs.
