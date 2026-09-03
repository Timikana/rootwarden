# DOSSIER 04 — Les correctifs des gestes distants (E-214, E-215, E-219, E-225)

**Pour signature de l'exploitant.** Préparé par la session 8 le **2026-08-28**.

> **Ce dossier a rétréci en cours de mesure.** Il devait porter *« les correctifs des gestes distants,
> à qualifier avant écriture »*. **Deux des quatre sont écrits, commités et n'attendent que le
> redémarrage.** Ce qui reste à signer est plus étroit — et plus lourd.

---

## 1. Recommandation

| écart | état mesuré | ce que je recommande |
|---|---|---|
| **E-214** `sshd_allow_user` | **CORRIGÉ** — `77ae2c2` | rien à décider : **c'est le `DOSSIER-01`** |
| **E-215** `remove_user_keys` | **CORRIGÉ** — `52838f2` | idem |
| **E-219** étendre la révocation aux 3 copies de la clé | **non écrit** | **NE PAS l'écrire.** Corriger le texte (délégué, `DECISIONS-DSI.md` §3) |
| **E-225** retirer le dépôt Wazuh à la désinstallation | **non écrit** | **NE PAS l'écrire.** Le dire (délégué, §4) |

**Les deux recommandations de ce dossier sont donc des refus**, et c'est le résultat le plus utile
qu'il pouvait produire : *deux gestes destructeurs de moins à mettre en service, et deux textes vrais
de plus.*

---

## 2. Conséquence, mesurée

### E-214 et E-215 : écrits, lus, et inertes

    77ae2c2  fix(ssh): E-214 - le `|| true` rendait le retour arriere inatteignable
    52838f2  fix(ssh): E-215 - la garde ET la verification, dans le meme commit

**E-214.** `_RELOAD_SSHD` ne porte plus de `|| true`, le code de retour est lu (`ssh.py:172`, `:241`), et
le retour arrière rend `(restaure, message)` où **le message DIT que le fichier est resté modifié** quand
il échoue — *« c'est l'information que l'ancienne version supprimait »*. Sauvegarde `.bak.rw`, validation
`sshd -t`, retour arrière complet.

**E-215.** Les trois changements sont là : sélection **par empreinte** et non par sous-chaîne, clé de
plateforme protégée comme chez sa voisine, code de sortie lu. **Et la mesure qui justifiait le premier est
dans la docstring** : sur trois clés réelles, le `sed -i '/rootwarden/d'` en retirait **deux**, dont une clé
**personnelle** commentée `backup-from-rootwarden-host` ; le retrait par empreinte en retire **une**.

> **Et le correctif a été livré dans le bon ordre, ce qui est le point le plus instructif** : *« la
> vérification seule aurait armé le piège »*. Faire lire son code de retour à la route la rend **effective
> à chaque fois**, y compris quand elle retire la clé de plateforme. **La garde et la vérification sont
> dans le même commit.**

**Les deux sont inertes** — `backend/**.py` est lu au démarrage, `StartedAt = 2026-08-27T12:28:43Z`, les
fichiers sont postérieurs. **Ils ne protègent rien tant que le `DOSSIER-01` n'est pas signé.**

### E-219 : pourquoi ne PAS étendre le geste

`revoke_service_account` supprime le compte de service et laisse la clé de plateforme autorisée sur
**`root`** et sur le **compte nominal** — trois copies, une retirée.

    ssh.py:745   >> ~/.ssh/authorized_keys              compte NOMINAL    APPEND
    ssh.py:755   >> /root/.ssh/authorized_keys          ROOT              APPEND
    ssh.py:808   >  /home/<sa>/.ssh/authorized_keys     compte de service ECRASE

**Étendre le geste aux trois rendrait RootWarden incapable de joindre la machine autrement que par mot de
passe.** Et le parc mesuré rend ce coût concret : `srv-zabbix` porte
`service_account_deployed = 1`, `platform_key_deployed = 1`, et ses deux mots de passe **ont été
ressaisis par l'exploitant**. Sur une machine où ils ne l'auraient pas été, une révocation étendue serait
**un verrouillage définitif** — la classe E-201 / E-202, atteinte par le bouton censé protéger.

> **Le geste ne doit pas grandir : c'est son TEXTE qui doit rétrécir.** L'étiquette `kill-switch` et les
> trois cas d'usage partent, et le texte nomme la chaîne réelle. *Un coupe-circuit qui ne coupe pas est
> pire qu'un coupe-circuit absent — son absence fait chercher une autre parade.*

**Et la chaîne réelle existe, elle n'a simplement pas d'interface de parc** : `regenerate_platform_key`
remplace la clé **employée** (elle ne retire rien des machines, E-226), puis `server_user_remove_key`
retire l'ancienne **compte par compte et machine par machine**. **`server_user_remove_key` est la route
soigneuse du fichier** — sauvegarde, empreintes recalculées, refus par défaut sur la clé de plateforme,
code de retour lu. *Ce n'est pas elle qui porte E-215 ; c'est `remove_user_keys`, sa voisine* — la
confusion a déjà été faite trois fois, le Lead compris.

### E-225 : pourquoi ne PAS retirer le dépôt

`uninstall` laisse `/usr/share/keyrings/wazuh.gpg` et `/etc/apt/sources.list.d/wazuh.list`.

**Le dédouanement est réel** : keyring **dédié**, dépôt `signed-by=` ce keyring — **ce n'est pas un
`apt-key add`**, la confiance est bornée à ce dépôt et n'est pas globale. **Et un exploitant peut
légitimement vouloir garder le dépôt** pour réinstaller sans refaire l'amorçage.

**Ce qui pèse contre l'écriture du geste** : `wazuh_agents` porte **0 ligne** — aucune route de ce module
n'a jamais servi. *On n'ajoute pas une option destructrice à une capacité qu'on n'a jamais vue
fonctionner.*

---

## 3. Le geste exact

**Pour E-214 et E-215 : aucun geste propre.** Ils entrent en service avec le `DOSSIER-01`, et l'unique
chose à faire est de **les observer parmi les 19 modules** plutôt que d'attendre le seul correctif qu'on
guettait.

**Pour E-219 et E-225 : deux écritures de texte, aucune écriture distante.**

```
backend/routes/ssh.py     docstring de `revoke_service_account`
                          - retirer l etiquette `kill-switch` et les 3 cas d usage
                          - dire ce que le geste LAISSE en place
                          - nommer la chaine reelle, et nommer `server_user_remove_key`
                            (PAS `remove_user_keys`)

backend/routes/wazuh.py   reponse de `uninstall`
                          - nommer ce qui subsiste : le depot et sa cle de signature
                          - et derouler d une SEULE implementation de l amorcage,
                            aujourd hui ecrite deux fois (:366 et :525)
```

**Périmètre : session 4** (`backend/`). **§3.2 autorise ces écritures** — ce sont des textes et une
réponse, aucun changement de comportement distant. **Verrouillé par la session 6.**

**Le geste que ce dossier NE demande PAS d'autoriser**, et c'est son objet : ni l'extension de la
révocation, ni le retrait du dépôt.

---

## 4. Ce qui se passe si on ne fait rien

**Deux régimes, et ils ne vont pas dans le même sens.**

**Sur E-214 et E-215 — ne rien faire, c'est laisser les défauts OUVERTS.** Les correctifs existent et
ne protègent personne :

| | ce qui reste vrai tant que le service n'a pas redémarré |
|---|---|
| E-214 | `sshd_allow_user` **atteste « AllowUsers patché »** même si `sshd` n'a jamais rechargé. Le portail affirme un durcissement qui n'a pas eu lieu, **donc personne ne le refera** |
| E-215 | une **révocation d'accès** est attestée sans être vérifiée, et son mode sélectif retire par **sous-chaîne** : une clé personnelle commentée `backup-from-rootwarden-host` saute en silence |

> *Une fausse attestation est la pire forme du motif : personne ne rouvre un dossier de conformité
> clos.* **Ces deux-là sont réparés et l'attente les maintient en vigueur.**

**Sur E-219 et E-225 — ne rien faire laisse deux textes faux**, et l'un est lu **pendant un incident** :

- **E-219** : tant que la docstring désigne la révocation pour une compromission, **le geste qui répond
  réellement au cas n'est documenté nulle part.** *Un texte faux retiré sans son remplacement rend la
  désinformation muette ; un texte faux laissé la propage.* Et il n'existe **aucun geste unique** qui
  réponde à une clé compromise — la rotation ne la révoque pas non plus, `authorized_keys` étant écrit
  en append ;
- **E-225** : le bouton s'appelle « désinstaller » et rien ne dit ce qui reste. *Un geste réversible qui
  ne rend pas tout ce qu'il a pris n'est pas réversible : il est partiel, et le reste est invisible.*
  Coût de l'inaction : **nul aujourd'hui** — le module n'a jamais servi. Il devient réel au premier
  usage.

---

## Ce qui n'est pas mesuré

- **le comportement d'E-214 et E-215 en exécution.** Établis par lecture du code corrigé ; aucun geste
  distant n'a été émis ;
- **que les trois copies de la clé existent réellement sur les machines.** E-219 les établit par la
  lecture des quatre `printf` de `ssh.py` — *une lecture généralise là où une mesure trouve* — et la
  mesure d'empreintes de la session 5 portait sur ce parc, pas sur le code ;
- **si `_ensure_sshd_allows_user` ne patche toujours que la PREMIÈRE ligne `AllowUsers`**, et si un
  fichier `.conf` inclus primerait. Signalé par la session 4, jamais compté — **aucune machine pour le
  vérifier**, et cela n'a pas changé.
