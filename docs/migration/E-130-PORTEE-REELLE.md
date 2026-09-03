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

## ⚠ Réserve de cette mesure

Établie **par lecture**, sans clic. Le seul point de faux serait un désaccord de type entre
`self.machine['id']` et la clé `mid` de `sudo_policies` : les deux viennent du même
`cursor(dictionary=True)` sur des colonnes INT, donc ils s'accordent — mais c'est une
lecture, pas une exécution.
