# QA — `telegraf_output_token` stocké en clair : base vérifiée pour le correctif

**Mesuré le 2026-09-09, 09:30–09:55 CEST.** Lecture seule : aucune écriture, aucun
déploiement, aucun geste de supervision exercé.

> ⛔ **Ce document n'est pas un correctif et n'en propose pas.** Il établit ce qui EST,
> pour que celui qui écrira le code n'ait pas à re-mesurer. Deux contraintes n'étaient
> pas nommées dans la demande, et l'une des deux casse l'agent en silence.

## 1. Le défaut est confirmé, et la rétractation du pair aussi

| | `tls_psk_value` | `telegraf_output_token` |
|---|---|---|
| colonne | `VARCHAR(512)`, commentaire *« Chiffré en DB »* | `VARCHAR(512)`, aucun commentaire |
| écrivain | `:718` `encrypt_password(...)` | `:2475` / `:2499` — **brut** |
| lecteur | `:895` / `:1242` `decrypt_password` | `:541` — **brut** |
| commentaire | conforme | `:2464` *« Chiffrer le token Telegraf si fourni »* |

**Les deux côtés sont cohérents entre eux : le jeton est en clair par CONSTRUCTION**,
et son commentaire ratifie un chiffrement qui n'existe pas. Le masquage `'********'`
de `:2434-2435` protège **la réponse de l'API, pas la colonne** — c'est ce qui rend le
défaut invisible à toute lecture de l'interface.

**La table est VIDE — vérifié avec trois témoins dans la même commande :**

    supervision_config              0 lignes
    jeton non vide                  0
    jeton deja chiffre              0
    TEMOIN users (doit etre > 0)    10        ← la requete a bien atteint la base
    TEMOIN NEGATIF table inexistante  ERROR 1146, code de sortie 1
                                              ← l'instrument n'invente pas de vide

> Le défaut est **ARMÉ, pas exercé**. La première écriture dans cette colonne sera la
> première occasion. *La version « un secret est déjà en clair en service » était
> fausse et son auteur l'a retirée avant que je la mesure ; je confirme le retrait.*

---

## 2. ⛔ LA CONTRAINTE QUI N'ÉTAIT PAS NOMMÉE : le jeton part dans un FICHIER DÉPLOYÉ

`:541` n'est pas un lecteur d'affichage. Il alimente `_build_agent_config_content()`
(`:500-574`), appelée à `:1951` et `:2144`, et le jeton atterrit ici :

    :553  if output_url:
    :557      f'  token = "{output_token}"\n'      ← TOML Telegraf, sur la machine cible

> **Un correctif qui chiffre l'écriture sans déchiffrer à `:541` déploie
> `sodium:…` comme jeton.** Telegraf démarrera, la configuration sera valide, et
> **l'authentification échouera à la sortie InfluxDB** — pas au déploiement. Le
> symptôme apparaît loin du geste, dans un agent distant, sans erreur côté produit.

*C'est le même défaut de domaine que `working_dir` : le gage est posé au bon endroit
et le PUITS est ailleurs.* Ici le puits est un fichier de configuration distant.

## 3. ⛔ LA SECONDE : `VARCHAR(512)` borne le clair à **338 caractères**

Mesuré dans le conteneur, sodium disponible, **longueurs seules, aucune valeur** :

    clair  88  ->  chiffre 179   prefixe `sodium:`   aller-retour identique
    clair 200  ->  chiffre 327   prefixe `sodium:`   aller-retour identique
    plus grand clair tenant dans VARCHAR(512)  :  338 caracteres

**Chiffrer NARROWS l'entrée acceptée de 512 à 338 sans qu'aucune ligne ne le dise.**
Un jeton InfluxDB typique fait ~88 caractères, donc la borne n'est pas atteinte en
pratique — *mais elle devient une limite tacite du produit.*

**Le mode d'échec est visible, pas silencieux** : `@@sql_mode` porte
`STRICT_TRANS_TABLES`, donc un dépassement **lève** au lieu de tronquer. Une valeur
indéchiffrable ne peut donc pas s'installer en base par cette voie.

## 4. Ce qui est déjà satisfait, et qu'il suffit de ne pas casser

`encryption.py:183-184` — `if not password: return ""`. **Mesuré** : `''` et `None`
rendent tous deux `""`, longueur 0, sans préfixe.

> Les quatre sites du portage qui font `IS NOT NULL AND x <> ''`
> (`Supervision.php:297-298`, `ClePlateforme.php:65-66`) mesurent des **OCTETS** et
> non la présence d'un secret. Ils restent justes **tant que le chiffrement d'une
> entrée vide rend une chaîne vide.** C'est le cas aujourd'hui.

⚠ Et ces quatre sites sont sûrs **par contingence** : aucun écrivain PHP n'existe
pour ces colonnes. *La contingence n'est pas une garantie — elle tombe le jour où le
portage écrit.*

## 5. Ce qui n'est PAS un défaut, mesuré pour que personne ne le poursuive

Le jeton est interpolé brut dans du TOML (`:557`, entre guillemets) : une valeur
portant `"` ou un saut de ligne injecterait des directives Telegraf, y compris un
`[[inputs.exec]]`. **Capacité marginale : nulle.**

    extra_config  ->  ajoute VERBATIM au contenu genere (:519 :534 :570)
    meme route `POST /supervision/config/<platform>`
    memes gardes @require_role(2) + @require_permission('can_manage_supervision')

**Le même acteur peut déjà écrire du TOML arbitraire, par conception.** *Un défaut
dont l'exploitation demande une capacité déjà détenue et OFFERTE n'est pas une
élévation.*

## 6. La migration : rien à migrer, et c'est mesuré

`supervision_config` porte **0 ligne**, dont 0 avec un jeton. Aucune donnée existante
à convertir. *Écrire une migration ici produirait un fichier qui ne migre rien —
et la note du §1 suffit à justifier son absence.*

---

## 7. Ce que je n'ai pas fait, et pourquoi

**Je n'ai pas écrit le correctif.** Ma charge sur ce chantier est l'analyse du legacy
et la production de documents ; je suis en lecture seule sur le code, quel que soit le
répertoire. Le correctif demandé est court — chiffrer à `:2465`, déchiffrer à `:541`,
à l'image du PSK du même fichier — et les deux contraintes des §2 et §3 en changent le
contenu, pas la taille. **Il lui manque un exécutant, pas une spécification.**
