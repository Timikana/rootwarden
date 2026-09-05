# AUDIT — `politiques` : la capacité EST portée, et il n'y a pas de fichier legacy à archiver

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 22:42 CEST**.
`docs/` seul — la fenêtre du LOT est ouverte. **Aucun geste exercé.**

**Le DSI pose l'alternative : soit `sudo_preset` n'existe que dans le legacy —
et c'est un fichier non archivable — soit il est porté, et c'est la neuvième
fois. Mesuré : c'est la neuvième fois. ET il n'y avait de toute façon aucun
fichier legacy à archiver.**

---

## 1. Le lead qui a ouvert le relevé : une règle de step-up n'est pas écrite pour rien

`RoutesBackend::MOTIFS_STEP_UP` porte :

```
'#^/policy/(sudo|sftp)/(deploy|remove)$#'
'#^/policy/rollback$#'
```

> **On n'écrit pas une re-authentification pour un chemin que personne n'appelle.**
> *C'est l'artefact le plus fiable après les libellés — et il a désigné la
> capacité avant que je n'ouvre le JS.*

---

## 2. ⚠ `sudo_preset` à « 0 occurrence » était un COMPTE DE NOM

**Le geste est porté, et son chemin est COMPOSÉ** — forme n°3 des cinq :

```js
politiques.js:237   return appelle('/policy/sudo/' + geste, envoi)…
politiques.js:195   var estDeploiement = (geste === 'deploy');
```

**`geste` ∈ {`deploy`, `remove`}.** *Un motif littéral sur `/policy/sudo/deploy`
rend **zéro** sur une capacité entièrement présente* — exactement le piège que le
DSI décrit, et la seconde fois qu'il mord dans mes relevés.

**Et le préréglage est offert**, pas seulement supporté :

```
politiques.blade.php:65   <select name="preset" data-rw="politique-prereglage">
politiques.js:95          preset: choixPrereglage.value
```

### 2.1 Le portage a DURCI ce geste, il ne s'est pas contenté de le porter

```
:84  « `preset` PART TOUJOURS, et ce n'est pas une precaution de style :
      `sudo_deploy` fait `data.get('preset', 'apt_only')`. Une requete qui
      l'omet obtient donc le prereglage EQUIVALENT ROOT. Le repli dangereux
      n'est pas seulement a l'ecran, il est aussi dans le backend. »
```

**Et l'observation est juste** : `apt_only` autorise `apt` en root, donc
l'installation d'un paquet arbitraire — **root en pratique**. *Un repli qui
retombe du côté permissif, dans le backend, et le portage refuse de s'y exposer
en envoyant toujours la valeur.*

**Second durcissement mesuré** : le legacy laissait `deployPolicy()` partir au
premier clic et ne confirmait que `removePolicy()`. **Le portage confirme les
deux.**

---

## 3. ⚠ ET IL N'Y A PAS DE FICHIER LEGACY À ARCHIVER — la prémisse tombe deux fois

```
legacy/policies/        AUCUN repertoire
legacy/politiques/      AUCUN repertoire
legacy/lang/{fr,en}/policies.php   EXISTENT
  -> et AUCUNE page legacy n'emploie ces cles (hors lang/ et _deprecated/)
```

**La page n'existe plus.** *Il ne reste que deux fichiers de langue ORPHELINS.*

> **La question « ce fichier est-il le seul accès ? » n'avait pas d'objet : il
> n'y a pas de fichier.** *Ce que le relevé débloque n'est pas un archivage —
> c'est une entrée fausse dans le catalogue.*

---

## 4. ⚠ DEUX RÉSIDUS RÉELS, ET ILS SONT L'INVERSE DU LEAD

Mon lead disait : *une règle de step-up désigne un chemin qu'on appelle.* **Vrai
pour `sudo/deploy|remove`. Faux pour les deux autres :**

| chemin | step-up armé | appelé par le portage |
|---|---|---|
| `/policy/sudo/deploy` · `remove` | oui | **oui** (composé) |
| `/policy/rollback` | **oui** | **NON** — seulement *mentionné* dans un docstring qui décrit ce que faisait le legacy |
| `/policy/sftp/deploy` · `remove` | **oui** | **NON** — `sftp` : **zéro occurrence** dans le module porté |

> **Deux chemins portent une re-authentification et ne sont atteignables depuis
> AUCUNE interface du portage.** *Le step-up y est donc armé pour une requête
> forgée — il mordrait, ce qui est bon — mais personne ne peut les employer
> légitimement.*

**Ce sont deux capacités non portées que rien ne déclare** : ni un libellé, ni un
bouton, ni une entrée de catalogue. **Seule la table de step-up en garde la
trace.** *C'est la forme la plus discrète du manque — et la table qui la porte
est une garde, pas un inventaire : personne ne la lit pour savoir ce qui existe.*

**Troisième résidu, mineur** : `legacy/lang/{fr,en}/policies.php` sont orphelins.

---

## 5. Le témoin, posé avant de conclure

    'deploy' dans politiques.js   7 occurrences   -> la sonde n'est pas aveugle
    'sftp'   dans politiques.js   0               -> c'est une MESURE, pas un silence
    'sftp'   dans la vue          0

*Sans le premier, « zéro `sftp` » et « ma sonde ne lit pas ce fichier » auraient
été indiscernables.*

---

## 6. Non mesuré, et dit

- **je n'ai exercé aucun geste** : ni déploiement, ni retrait, ni page ouverte ;
- je n'ai pas vérifié si `/policy/rollback` et `/policy/sftp/*` **existent** côté
  backend — mon relevé porte sur ce que le PORTAGE appelle. *S'ils n'existaient
  pas, les motifs de step-up seraient orphelins des deux côtés, ce qui serait un
  quatrième résidu et non un manque.* **Question ouverte, non tranchée.**
