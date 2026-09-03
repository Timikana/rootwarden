# DOSSIER 19 — Le préréglage sudo le PLUS RESTRICTIF accorde le root complet

**⚠ POUR SIGNATURE URGENTE. Défaut de PRODUCTION, pas de portage.** *Trouvé par la session 3 le
2026-09-03 ; chaîne revérifiée par moi maillon par maillon à 11:00 CEST.*

> **Un administrateur qui choisit « systemctl — services spécifiques », le préréglage le plus étroit du
> menu, obtient `ALL=(ALL:ALL) NOPASSWD: ALL` sur la machine au déploiement suivant.** *Idem pour
> « custom ».*

---

## 1. La chaîne, maillon par maillon

    1. l'ECRAN offre SEPT prereglages
       legacy/lang/*/admin.php:35   access.sudo_preset_systemctl_specific
                            :36   access.sudo_preset_custom  (« custom (voir Avance) »
                                    — et il n'y a PAS d'onglet Avance)

    2. la ROUTE les accepte tous les sept
       update_server_access.php  $ALLOWED_PRESETS = none · all_nopasswd ·
         restart_services · apt_only · read_logs · systemctl_specific · custom

    3. mais elle n'ECRIT que TROIS colonnes
       :122  UPDATE user_machine_access SET sudo_preset = ?, sudo_nopasswd = ?, sudo_runas = ?
             -> ni `sudo_custom_rules`, et AUCUNE colonne de services n'existe

    4. la migration 051 ajoute QUATRE colonnes, et pas celle qu'il faudrait
       ADD COLUMN sudo_preset · sudo_nopasswd · sudo_runas · sudo_custom_rules
       -> AUCUNE colonne de SERVICES dans `user_machine_access`

    5. `sudo_custom_rules` n'est ECRIT PAR PERSONNE
       enumeration, 4 fichiers la citent :
         ARCHITECTURE.md · CHANGELOG.md · ssh_utils.py (le SELECT, LECTEUR)
         · migration 051 (le ADD COLUMN)
       -> ZERO ecrivain, dans tout le depot

    6. au deploiement, le dict est donc TOUJOURS vide sur ces deux champs
       configure_servers.py:369   'custom_rules': policy.get('custom_rules') or ''
                          :370   'services':     policy.get('services') or []

    7. les deux rendus LEVENT sur entree vide
       sudo_manager.py:124  render_preset_systemctl_specific
                            if not services: raise ValueError(…)
                     :144  render_preset_custom
                            if not custom_rules or not custom_rules.strip(): raise ValueError(…)

    8. ⛔ ET LE REPLI EST FAIL-OPEN, EXPLICITEMENT
       configure_servers.py:373-380
         except (ValueError, ImportError) as e:
             logger.error(f"[{username}] Render sudo policy invalide ({e}), fallback NOPASSWD ALL")
             policy = None
         if not policy or not policy.get('preset'):
             content = f"{username} ALL=(ALL:ALL) NOPASSWD: ALL\n"

> **Un préréglage que le moteur refuse ne produit pas un échec : il produit la règle la plus permissive
> possible.** *Et le journal l'écrit — « fallback NOPASSWD ALL » — dans un fichier que personne ne lit
> pendant un déploiement.*

---

## 2. Ce qui est en jeu, et ce qui le borne

**Deux des sept préréglages sont dans ce cas, TOUJOURS** — *pas dans un cas limite : par construction,
puisque aucune colonne ne peut porter leur entrée requise.*

    systemctl_specific   le prereglage le PLUS ETROIT du menu   -> root complet
    custom               etiquete « voir Avance », sans onglet Avance   -> root complet

**Ce qui le borne** : *l'écriture exige le rôle 3 (`update_server_access.php`), et l'application exige un
déploiement — geste réservé.* **Ce n'est donc pas une escalade ouverte : c'est un piège pour
l'administrateur légitime, qui croit restreindre et élargit.**

**Et un troisième, à SIGNALER et non à retirer :**

    sudo_manager.py:95-99   « AVERTISSEMENT : ce preset est EQUIVALENT ROOT.
                              `apt install/upgrade` … peut obtenir un shell root
                              via un paquet construit. »

**`apt_only` se présente comme plus étroit que `all_nopasswd` et ne l'est pas.** *Le code le dit dans son
propre docstring ; aucun écran ne le dit à la personne qui choisit.*

---

## 3. Le geste exact — et l'ORDRE compte

```
1. RETIRER LE FAIL-OPEN     configure_servers.py:373-380
   un render qui echoue doit ECHOUER, pas replier sur la regle maximale.
   -> le compte ne recoit AUCUNE regle sudo, et le deploiement le DIT.

2. RETIRER LES DEUX PREREGLAGES DU MENU  (ou ajouter les colonnes manquantes)
   -> une liste fermee dont deux valeurs mènent au root n'est pas une liste fermee

3. RELEVER LA BASE : y a-t-il des lignes deja ecrites ?
   SELECT user_id, machine_id, sudo_preset FROM user_machine_access
    WHERE sudo_preset IN ('systemctl_specific','custom');
   -> CHACUNE repliera en NOPASSWD: ALL au prochain deploiement

4. AFFICHER L'AVERTISSEMENT `apt_only` a l'ecran
```

**⚠ Le point 3 est celui qui ne peut pas attendre le portage** : *démonter le legacy retire l'ÉCRAN, il ne
retire pas les LIGNES.* **Un `sudo_preset = 'systemctl_specific'` posé hier restera en base et repliera au
prochain déploiement, longtemps après la disparition du menu qui l'a produit.**

**Et le correctif est du `backend/`, donc INERTE jusqu'au redémarrage** (`DOSSIER-01`) — *il appartient au
lot du redémarrage, pas à celui de la bascule.*

---

## 4. Pourquoi ça n'a pas explosé plus tôt

**Le dernier déploiement réel a été lancé sur la PRODUCTION le 27/08 à 22:43 CEST** (`machines=['1','2']`)
*et il a échoué à la phase de déchiffrement.* **Cette panne est RÉPARÉE** — un déploiement lancé
aujourd'hui franchirait cette étape.

---

## Ce qui n'est pas mesuré

- **combien de lignes portent ces deux préréglages en production.** *C'est la requête du point 3 ; `docker`
  est refusé depuis les sessions* ;
- **le fichier `sudoers` réellement produit.** *Toute cette chaîne est établie par LECTURE ; personne n'a
  lancé de déploiement, et c'est délibéré* ;
- **si le repli a déjà été emprunté.** *Le journal porte « fallback NOPASSWD ALL » — il faudrait lire les
  journaux de déploiement de production.* **C'est la première chose à chercher, et elle est
  cherchable : le message est littéral.**

---

## ⚠ Une rectification de méthode, signalée par la session 3 elle-même

**Son premier relevé classait `ssh_utils.py` comme ÉCRIVAIN de `sudo_custom_rules`.** *Faux : sa regex
`(INSERT|UPDATE|SET)…sudo_custom_rules` a mordu à 200 caractères de distance sur le `SELECT` du
collecteur.* **La conclusion tient par l'ÉNUMÉRATION des 4 fichiers, pas par la regex** — *et c'est le
même piège que mon `grep -l` de ce matin, chez elle, une heure après qu'elle me l'a signalé.*
