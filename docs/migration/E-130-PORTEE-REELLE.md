# E-130 — la sévérité écrite est périmée : le repli `NOPASSWD: ALL` est INATTEIGNABLE

**Mesure du 2026-09-03, par LECTURE de la chaîne, sans l'exercer.**

`MODULE-ADM.md §5.0decies` et `PLAN-DE-MIGRATION.md:1649` écrivent :

> *« l'import écrit `users.sudo = 1` sans aucun contrôle de rôle […] Or `users.sudo` est la
> précondition du repli `NOPASSWD: ALL` de `ssh/` »*

**La première moitié tient — vérifiée à la source :**

    import_csv.php:162   $sudo = (int)($data['sudo'] ?? 0);        AUCUNE garde
    import_csv.php:166   ->execute([… $roleId, $active, $sudo]);
    toggle_sudo.php:26   checkAuth([ROLE_SUPERADMIN]);  // le geste dedie
    toggle_sudo.php:47   refuse meme de modifier SON PROPRE sudo

**La seconde ne tient plus.**

## Pourquoi le repli ne s'atteint pas

    configure_servers.py:1050   if  policy && preset && preset != 'none'  -> add_to_sudoers(policy)
                     :1052      elif policy && preset == 'none'           -> remove_from_sudoers
                     :1054      elif sudo                                 -> add_to_sudoers()  # NOPASSWD ALL
                     :1057      else                                      -> remove_from_sudoers

La troisième branche exige `policy_for_machine is None`. Or les deux structures qu'elle
oppose sont remplies par **le même bloc** :

    ssh_utils.py:957   if mid:  users_dict[uid]['allowed_servers'].append(mid)
    ssh_utils.py:958            users_dict[uid]['sudo_policies'][mid] = {'preset': … or 'none', …}

Et `configure_user` n'est atteint que par `configure_users:930`, gardé par
`if mid in user.get('allowed_servers', [])`.

> **`mid ∈ allowed_servers` ⟹ `sudo_policies[mid]` existe ⟹ `policy_for_machine` est vrai
> ⟹ l'une des deux premières branches tire TOUJOURS.** Le dict est toujours non vide donc
> truthy, et `preset` vaut `'none'` par défaut, jamais `None`.

**Enumération, pas motif** : `configure_user` a **un seul** appelant de production (`:932`) ;
`self.all_users` vient de `load_data_from_db` (`:1197`), donc du seul constructeur
(`ssh_utils:957-958`) ; `sudo_policies` n'est lu qu'en `:1046-1047`. Les **deux** seuls
lecteurs du drapeau dans tout `backend/` sont `ssh_utils:950` (qui le recopie) et
`configure_servers:1022`. *Témoin : `deploy_user_config` existe et ne lit pas `sudo`.*

## Ce que cela retire, et ce que cela AJOUTE

    RETIRE   aucune regle sudoers n'atteint une machine aujourd'hui depuis un `sudo=1`
             importe. L'urgence tombe.
    AJOUTE   un privilege ACCORDE et INERTE : il dort en base, aucun test ne l'exerce,
             aucun ecran ne montre qu'il ne fait rien — et il revit au premier changement
             du collecteur ou de la branche.

**Un privilège inerte est pire qu'un privilège visible : rien ne le mesure.** La page des
comptes l'affiche comme accordé, et il l'est en base. E-130 reste donc un défaut de moindre
privilège et d'intégrité — **il n'est pas un chemin d'escalade vivant.**

**Conséquence pour l'arbitrage** : si l'exploitant tranche la colonne `sudo` en croyant
qu'un import écrit aujourd'hui des règles sudoers sur des machines réelles, il tranche sur
un fait qui n'existe plus. L'énoncé se dit en trois temps : *le privilège est accordé en
base · il n'atteint aucune machine par le chemin actuel · il redevient effectif si la
branche ou le collecteur change.*

## La forme de l'issue (a) n'est pas tranchée, et elle compte

« Exiger le rôle 3 pour cette colonne » ne dit pas ce qu'un rôle 2 obtient.

    ce que fait `role_id`   :156  if ($myRole < 3 && $roleId >= $myRole) { $roleId = 1; }
                            coercition SILENCIEUSE — l'importeur n'apprend rien
    ce qui existe deja      :143  $results['errors'][] = "Ligne $lineNum ($name) : doublon ignore";
                            un canal PAR LIGNE, deja utilise

**Coercer `sudo` à 0 ET rendre compte par ligne**, avec la machinerie qui existe. Un
importeur qui croit avoir accordé sudo et ne l'a pas accordé prendra la décision suivante
sur une croyance fausse. *Le même angle mort vaut pour la coercition de `role_id` — correcte
et muette : second arbitrage, plus petit, à ne pas perdre.*

## ⚠ PLUS FORT QUE « INERTE » : LE DÉPLOIEMENT *RETIRE* LE SUDO

Relevé par la session DSI en revérifiant la chaîne, et confirmé ici. Avec `preset = 'none'`, ce
n'est pas la troisième branche qui est sautée : **c'est la deuxième qui tire.**

    elif policy_for_machine and policy_for_machine.get('preset') == 'none':
        remove_from_sudoers(channel, username, …)

**La base dit « accordé », la page l'affiche accordé, et le déploiement le RETIRE.** Un privilège
accordé et *contredit*, pas seulement inerte.

## ET LE REPLI EST MORT PAR LE SCHÉMA, PAS PAR UN DÉFAUT DU COLLECTEUR

    051:7   sudo_preset ENUM('none','all_nopasswd',…) NOT NULL DEFAULT 'none'

**`NOT NULL`** : la colonne n'est jamais nulle, donc `policy_for_machine` est toujours un dict
plein. Le `record.get('sudo_preset') or 'none'` de `ssh_utils:959` n'est donc même pas la cause.
*L'intention écrite juste au-dessus de la branche — « policy=None -> fallback bool users.sudo » —
décrit un cas que le schéma rend impossible. **Un commentaire qui affirme plus que le code.***

Et `051:37-38` fait un rattrapage **à un coup** :

    SET uma.sudo_preset = 'all_nopasswd', uma.sudo_nopasswd = TRUE
    WHERE u.sudo = 1 AND uma.sudo_preset = 'none';

Les comptes antérieurs à 051 ont donc été convertis. **Rien ne rattrape ceux d'après.**

## ⚠ CE QUI RENVERSE E-130 : LE GESTE DE RÔLE 3 EST LUI AUSSI SANS EFFET

    toggle_sudo.php:61    UPDATE users SET sudo = ? WHERE id = ?      <- users.sudo SEUL
    le seul ecrivain de sudo_preset :
    update_server_access.php:123   UPDATE user_machine_access SET sudo_preset = ?, …
    declencheur SQL qui rattraperait : AUCUN (0 CREATE TRIGGER dans les migrations)

> **`users.sudo` ne confère plus rien sur aucune machine — ni par l'import, ni par le geste de
> rôle 3 que le dossier cite comme la référence bien gardée.** Le seul chemin d'octroi vivant est
> la liste déroulante de préréglage de `manage_access.php`.

E-130 n'est donc pas « une escalade par fichier ». C'est **une interface de privilège qui ment
dans les deux sens** : elle montre accordé ce qui ne l'est pas, et le déploiement défait
silencieusement ce qu'elle affiche — y compris pour un rôle 3 faisant le geste légitime.

## ⚠ LA SÉVÉRITÉ N'EST PAS NULLE : ELLE EST DIFFÉRÉE

**Le jour où quelqu'un répare `toggle_sudo.php` en écrivant aussi `sudo_preset`, tout compte
portant `users.sudo = 1` obtiendrait `NOPASSWD: ALL` sur chaque machine qu'il atteint** — les
comptes importés sans garde inclus.

**C'est l'argument le plus fort pour l'issue (a), et il impose un ORDRE :**

    1. garder la colonne `sudo` a l'import  (role 3, coercition + compte-rendu par ligne)
    2. SEULEMENT ENSUITE reparer le chemin d'octroi

*Réparer (2) avant (1) armerait par un correctif ce que le correctif venait empêcher.*

## ⚠ Réserve de cette mesure

Établie **par lecture**, sans clic. Le seul point de faux serait un désaccord de type entre
`self.machine['id']` et la clé `mid` de `sudo_policies` : les deux viennent du même
`cursor(dictionary=True)` sur des colonnes INT, donc ils s'accordent — mais c'est une
lecture, pas une exécution.

**Deuxième réserve** : `mid` (clé de `sudo_policies`, issue de `record.get('machine_id')` dans la
requête de `ssh_utils`) et `self.machine['id']` viennent de **deux requêtes distinctes**, non du
même `cursor` comme je l'avais d'abord écrit. Ils s'accordent parce que les colonnes sont INT.
*Correction apportée par la session DSI.*
