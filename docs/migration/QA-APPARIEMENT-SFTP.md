# `sftp` — appariement clé par clé contre ce que le JS APPELLE

**Mesuré le 2026-09-08 entre 10:45 et 10:55 CEST**, en lecture d'arbre. Aucun accès
SFTP ouvert ni révoqué, aucune machine jointe.

> ## Verdict : **65 clés · 4 familles de geste · les QUATRE atteignables**, chacune
> avec son site d'appel. **Une seule clé nomme un geste inatteignable** — et ce n'est
> pas un défaut.

---

## 1. ⚠ L'instrument fourni rapporte le HELPER, pas ses APPELANTS

    analyse-appelants.mjs  ->  acces-sftp.js:98  appelle()  -> PASSERELLE + chemin
                               UN site, classe « verifie »

**`:98` est la définition interne du helper `appelle()`** — son propre `fetch`. Les
**trois** sites d'appel réels sont ailleurs :

    :216   appelle('/policy/sftp/' + geste, envoi)      <- chemin CONSTRUIT
    :260   appelle('/policy/rollback', …)
    :289   appelle('/policy/sftp/audit', …)

> **Un outil qui trouve le `fetch` trouve le helper, jamais les gestes.** Le helper
> est le seul endroit où le `fetch` littéral apparaît ; les gestes sont dans ses
> appelants. *C'est l'inverse de ce qu'on cherche, et le résultat — « un seul site »
> — a la forme d'un inventaire complet.*

---

## 2. Les valeurs de `geste`, énumérées À LEUR SOURCE

    acces-sftp.js:198   .addEventListener('click', () => ouvre('deploy'))
    acces-sftp.js:200   .addEventListener('click', () => ouvre('remove'))

**Deux valeurs, et deux seulement** — les écouteurs de la page sont la source. Le code
les confirme par ses propres tests : `:173` `geste === 'deploy'`, `:233`
`geste === 'remove'`.

**Correspondance exacte avec ce que le backend déclare :**

    backend/routes/policies.py:347   /policy/sftp/deploy
    backend/routes/policies.py:452   /policy/sftp/remove
    backend/routes/policies.py:423   /policy/sftp/audit
    backend/routes/policies.py:524   /policy/rollback

**Quatre routes déclarées, quatre gestes appelés, aucun orphelin de part ni d'autre.**

---

## 3. Les 65 clés : 22 nomment un geste, 43 non

| famille de geste | clés | site d'appel qui le PROUVE | atteignable |
|---|---|---|---|
| **déployer** | `deployer` · `aide_deployer` · `confirmer_titre` `_intro` `_machine` `_compte` `_effet` `_ouvre` `_valider` | `:198` → `:216` → `/policy/sftp/deploy` | ✅ |
| **retirer** | `retirer` · `aide_retirer` · `retirer_titre` `_intro` `_valider` | `:200` → `:216` → `/policy/sftp/remove` | ✅ |
| **auditer** | `auditer` · `aide_auditer` | `:289` → `/policy/sftp/audit` | ✅ |
| **annuler un déploiement** | `rollback` · `rollback_titre` · `rollback_texte` · `rollback_confirme` | `:260` → `/policy/rollback` | ✅ |
| — | `confirmer_annuler` | ferme un panneau, **pas un geste distant** | s.o. |
| ⚠ | **`rollback_lien`** | **aucun** | ⛔ voir §4 |

**Les 43 autres** sont des étiquettes de champ (`f_*`), des aides (`h_*`), des états
(`etat_*`), des titres et des messages de résultat. *Elles ne nomment aucun geste :
la question « est-il atteignable » n'a pas d'objet pour elles.*

---

## 4. La seule clé de geste inatteignable — **et c'est une trace de succès**

    sftp.rollback_lien   « Annuler ce deploiement dans l'ancien portail »
                         consommateurs : ZERO

**Le geste qu'elle nomme EST porté** — `/policy/rollback` est appelé à `:260`, et
`rollback_texte` décrit aujourd'hui *« restaure le bloc SSH exact d'avant ce
déploiement »*, rendu comme `title=` d'un **bouton** (`acces-sftp.blade.php:234`).

> **La clé est le résidu d'un portage terminé** : le geste a été porté, le texte
> réécrit, le lien vers l'ancien portail retiré de la vue — et seule la clé est
> restée. *Le même résidu existe dans `politiques` et `bashrc`, sous le même nom.*
>
> **Qui la retirera nettoiera ; il ne réparera rien.**

*Second orphelin du catalogue, mesuré par `cles-atteintes.py` : `sftp.restreint` — une
étiquette, pas un geste.*

---

## 5. Ce que je ne peux pas prouver

- **je n'ai exercé aucun geste** : « le JS compose la requête » n'est pas « le geste
  aboutit ». Les quatre routes existent et sont appelées ; qu'elles réussissent sur
  une machine réelle n'est pas dans ce relevé, et ne pouvait pas y être ;
- `confirmer_annuler` et les clés de step-up (`sftp-panneau-stepup`,
  `sftp-stepup-*` côté vue) relèvent d'un flux de re-authentification que je n'ai pas
  apparié ici ;
- **la parité est vérifiée par le COMPTE et par l'écart d'ensembles** (fr=65, en=65,
  écart vide), pas par la traduction de chaque valeur.
