# Patchs préparés, vérifiés, **non appliqués**

Session 4. Persistés le **2026-09-03**, sur l'observation du Lead : *un patch vérifié qui ne vit que
dans un contexte de session n'attend pas une signature, il attend une compaction.*

> **Le journal n'est pas l'autorité — l'artefact l'est.** Ces fichiers sont hors `backend/`,
> `laravel/`, `legacy/` et `tests/e2e/` : **le gel du banc ne les couvre pas, et ils sont inertes.**

---

## Le régime de génération est ce qui les distingue

**Un patch ne se juge pas seulement sur ce qu'il change, mais sur l'arbre CONTRE lequel il a été
généré.** Deux de ces fichiers visent des arbres différents, et l'un doit **refuser** sur `HEAD`.

| | patch | régime | contrôle |
|---|---|---|---|
| 01 | `E-231-psk-illisible` | **HEAD** | `git apply --check` passe |
| 02 | `E-280-portee-scheduler` | **HEAD** | `git apply --check` passe |
| 03 | `telegraf-jeton-en-clair` | **HEAD** | `git apply --check` passe |
| 04 | `E-281-apres-fusion` | **`a345e65`** (après fusion de `security/backend-cve`) | `patch --dry-run` passe sur l'arbre post-fusion, **et `git apply --check` REFUSE sur `HEAD`** |

**Le refus du 04 sur `HEAD` est le contrôle, pas un défaut** : un apport destiné à l'après-fusion qui
s'appliquerait *aussi* sur `HEAD` viserait les mauvaises lignes — c'est-à-dire exactement le conflit
qu'on cherche à éviter.

## Ce que chacun ferme

**01 — `E-231`, la clé PSK illisible.** Le commentaire du code déclare l'étape « DECISIVE quand une
PSK est configurée », et la garde est `if psk_value:`. Or `psk_value` vaut `None` **et** quand aucune
PSK n'est configurée, **et** quand le déchiffrement a échoué — ce dernier n'étant qu'un
`logger.warning`. Le bloc est sauté, rien n'entre dans `echecs`, et `_conclut_geste` émet
`SUCCESS_MACHINE::`. **L'agent part sans sa clé et le portail annonce la réussite.** Le patch couvre
aussi le cas d'une PSK qui **déchiffre en vide**.

**02 — `E-280`, la portée vide du planificateur SSH.** Les branches restreintes portent leur test de
vacuité **dans la condition d'entrée** (`and target_value`) : un champ laissé blanc n'entre jamais
dans sa propre branche et sort par le `else` final — **tout le parc**, sur une cron. Le patch pose une
branche `all` **explicite** et un `else` qui **refuse**. *Ce n'est pas une énumération de cas : c'est
un repli inversé, et il couvre les cinq branches d'un coup.*

**03 — le jeton Telegraf stocké en clair.** Le commentaire dit « Chiffrer le token Telegraf si
fourni » et la fonction ne contient **aucun** appel de chiffrement. **Les deux moitiés sont
indissociables** : chiffrer sans déchiffrer en lecture déploierait `sodium:…` comme jeton dans la
configuration de l'agent — *aujourd'hui le jeton est en clair et il **fonctionne** ; après, il serait
chiffré et **cassé**, silencieusement.*

**04 — `E-281`, ce que la fusion ne ferme pas.** `a345e65` rend la cible `machines` fail-closed et
exclut les archivées, mais **ne pose ni branche `all` explicite ni `else` qui refuse** : son dernier
`else` prend encore tout le parc vivant. Et ce chemin reste atteignable **par le schéma** —
`cve_scan_schedules.target_type` est `NULLABLE`, et `.get('target_type','all')` rend `None` sur un
`null` JSON explicite.

## ⚠ QUARANTAINE — ne pas appliquer

`QUARANTAINE-perime-refait-par-a345e65.patch` **s'applique sur `HEAD`**, et c'est précisément le
danger : son contenu est **déjà écrit** dans `security/backend-cve`. L'appliquer rendrait
conflictuelle une fusion aujourd'hui propre, **sur le hunk le plus sensible du dépôt**.

Il est conservé, et non supprimé, pour que personne ne le réécrive une troisième fois. *Un correctif
périmé qui garde le nom d'un correctif est un piège posé pour la session suivante — celui-ci porte son
état dans son nom.*

## Deux patchs retirés de ce dossier, et pourquoi

- **`E-280-portee-entree`** : **appliqué** le 2026-09-02 (`v1.38.180`). Il refuse sur `HEAD` parce
  qu'il y est déjà ;
- **`e187-forme`** : **appliqué** aussi — son contenu est présent dans `backend/routes/ssh.py`,
  vérifié par témoin positif.

*Un patch qui refuse peut être périmé OU viser un autre arbre. Les deux se distinguent en cherchant
son contenu dans l'arbre, pas en relisant son nom.*

## Remesure

```bash
for p in docs/migration/patchs-en-attente/0*.patch; do
  git apply --check "$p" && echo "OK   $p" || echo "refuse $p"
done
# le 04 DOIT refuser ; les 01 a 03 DOIVENT passer
```
