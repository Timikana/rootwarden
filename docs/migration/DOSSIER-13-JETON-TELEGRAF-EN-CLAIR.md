# DOSSIER 13 — Un secret stocké en clair, en production, sous un commentaire qui affirme le contraire

**Pour décision de l'exploitant.** Trouvé par la session 2 le **2026-09-02**, vérifié par moi à
**22:3x CEST**. *C'est le second dossier de la série dont l'objet soit un secret de production, après le
`DOSSIER-09`.*

---

## 1. Recommandation

| geste | recommandation |
|---|---|
| **vérifier en production** si `supervision_config` porte un jeton | **oui, et d'abord** — c'est le seul fait que je ne peux pas mesurer |
| **si un jeton y est** : le considérer comme **divulgué** et le faire **tourner** | **oui** — le rechiffrer ne suffit pas |
| **corriger le code** : chiffrer à l'écriture | **oui**, mais **avec le badge dans la même fenêtre** (§4) |

---

## 2. Le défaut, mesuré

    backend/routes/supervision.py, save_platform_config
      « # Chiffrer le token Telegraf si fourni »
      telegraf_token = data.get('telegraf_output_token', '')
      -> UPDATE supervision_config SET … telegraf_token …
      AUCUN appel de chiffrement dans la fonction

    TEMOIN, et il est decisif :
      le MEME fichier chiffre le PSK — `enc.encrypt_password(psk_value)` ligne 672

> **Ce n'est pas une capacité manquante : c'est un appel oublié, sous un commentaire qui affirme qu'il a
> lieu.** *Le fichier sait chiffrer. Il le fait pour un secret et pas pour l'autre.*

**Septième occurrence de l'en-tête qui ment sur ce chantier, et la première sur un secret.**

### Et c'est en production

    origin/main:backend/routes/supervision.py:1647   le meme commentaire
    -> 0 appel de chiffrement dans la fonction, cote `main` aussi

    le chemin d'ecriture est EN SERVICE sur le banc :
      supervision.py   2026-08-27 12:13   <   commit servi   2026-08-27 14:27

**Sur le banc, `supervision_config` porte ZÉRO ligne** — *rien à révoquer ici.* **Je n'interroge pas la
base de production, et c'est la seule mesure qui manque à ce dossier.**

---

## 3. Ce qui est en jeu, et ce qui ne l'est pas

**Un jeton de sortie Telegraf autorise l'écriture de métriques vers le collecteur.** *Ce n'est pas un
accès à une machine ; c'est un accès au flux de supervision.*

> **Ce que je ne peux pas qualifier** : *si ce jeton donne aussi la lecture, ou l'administration du
> collecteur, ou s'il est partagé avec d'autres systèmes.* **Ça dépend de votre configuration Telegraf,
> pas du code — et ça décide de la gravité.**

---

## 4. ⚠ LE PIÈGE : corriger le chiffrement CASSE le badge

**Mesuré par la session 2, et c'est ce qui gouverne l'ordre des gestes :**

    laravel/app/Services/Supervision.php:273
      (telegraf_output_token IS NOT NULL AND telegraf_output_token <> '') as jeton_pose

> **Ce test serait FAUX si la colonne était chiffrée** — *PHP chiffre `''` en `sodium:…`, donc la
> comparaison porterait sur des OCTETS et pas sur la présence d'un secret.* **Le badge est juste
> PRÉCISÉMENT parce que le chiffrement manque.**

**Chiffrer sans corriger le badge produirait un écran qui annonce « jeton posé » pour une colonne vide.**
*C'est le défaut que le registre appelle « une colonne vide, deux encodages » — et mon propre correctif
P1 avait cet angle mort.*

    1. chiffrer a l'ecriture         backend/routes/supervision.py   (session 4)
    2. ET corriger le test du badge  laravel/app/Services/Supervision.php:273   (session 3)
    -> les deux dans la MEME fenetre, ou le chiffrement partira seul et le badge mentira

**Les deux moitiés vivent dans deux périmètres différents. C'est ce qui rend l'oubli probable.**

---

## 5. Le geste exact

```
# ── 1. LE SEUL GESTE URGENT, et je ne peux pas le faire
#    en production :
#      SELECT id, (telegraf_output_token IS NOT NULL
#                  AND telegraf_output_token <> '') AS a_un_jeton
#      FROM supervision_config;
#    -> si a_un_jeton = 1 quelque part, le jeton est EN CLAIR en base

# ── 2. si un jeton existe : le faire TOURNER cote Telegraf
#    le rechiffrer ne suffit pas — il a ete stocke en clair, donc
#    il doit etre considere comme divulgue

# ── 3. le correctif de code, les deux moities ensemble (§4)
#    inerte jusqu'au redemarrage, comme les autres correctifs backend
```

---

## 6. Ce qui se passe si on ne fait rien

**Sur le banc : rien.** *Zéro ligne, aucun jeton, aucun risque.*

**En production : je ne sais pas, et c'est le problème.**

> **Un jeton stocké en clair ne se dégrade pas avec le temps — il attend.** *Toute personne ayant un
> accès en lecture à la base le lit : une sauvegarde, un export, un `SELECT` d'exploitation, un compte
> de service applicatif.* **Et il n'y a aucune trace de lecture à consulter après coup.**

**Le défaut existe depuis que le code existe** — *ce n'est pas une régression, et il n'y a donc pas de
fenêtre récente à examiner en priorité.* **Ça ne le rend pas moins vrai : ça veut dire que l'ancienneté
ne borne rien.**

---

## Ce qui n'est pas mesuré

- **si un jeton est stocké en production.** *La seule mesure qui décide, et elle vous appartient* ;
- **la portée de ce jeton chez Telegraf** — écriture seule, ou plus ;
- **s'il existe un chemin de LECTURE qui déchiffre déjà ce jeton.** *Si oui, il attend du clair et le
  correctif le casserait ; c'est la question que j'ai posée à la session 4 avant tout patch* ;
- **les autres colonnes de `supervision_config`.** *Seul `telegraf_output_token` a été examiné ; le même
  commentaire pourrait couvrir d'autres champs.*

---

# ⚠ RÉVISION — une PAIRE dans un seul périmètre, et ma crainte de blocage était fausse

**Le §4 ci-dessus est périmé.** *Trois mesures successives ont changé la forme du correctif, chacune en
RETIRANT un maillon.*

## 1. Il faut DÉCHIFFRER à la lecture, sinon le correctif casse le déploiement

    supervision.py:494   output_token = global_cfg.get('telegraf_output_token') or ''
                         -> ecrit TEL QUEL dans le contenu de configuration de l'agent
    appelants :1843 et :2034   — les DEUX chemins de deploiement

> **Chiffrer sans déchiffrer là déploierait `sodium:…` comme jeton, et l'agent échouerait à
> s'authentifier — silencieusement.** *Aujourd'hui le jeton est en clair et il **fonctionne** ; après, il
> serait chiffré et **cassé**.* **Le premier geste seul ne laisse pas un défaut : il en crée un pire.**

**`server_decrypt_password` est déjà importé (`:30`, employé `:204-205`) — rien à ajouter.**

## 2. ✅ Le badge n'a RIEN à corriger — j'avais routé une moitié Laravel à tort

    JETON   telegraf_token = data.get(…, '')   puis  if == '********' -> None
            -> une chaine VIDE serait stockee, donc CHIFFREE apres correctif
    PSK     if psk_value and psk_value != '********':      <- LE GARDE
            -> une chaine vide n'est JAMAIS chiffree

> **`psk_pose` n'est pas faux et ne le sera pas** : son garde amont garantit `NULL` ou un vrai secret.
> **Reprendre ce garde pour le jeton restaure l'invariant, et `<> ''` reste juste.**

**Formulation de la session 4, qui décrit sa propre erreur** — *elle avait généralisé du jeton vers le
PSK sans lire le second chemin* :

> **Un prédicat ne se juge pas sur la colonne, mais sur l'ensemble des valeurs qui peuvent y arriver.**

## 3. ⚠ J'ai bloqué le patch sur une crainte, et elle était fausse

**Je craignais que le garde retire la capacité d'effacer un jeton. Mesuré :**

    legacy/_deprecated/supervision/js/main.js:201
      data.telegraf_output_token = document.getElementById('cfg-telegraf-token').value || null;
    -> un champ vide envoie `null`, pas `''` -> COALESCE gardait DEJA l'ancien

    supervision.py:681-683   # UPDATE - conserver l'ancien PSK si non modifie
                             -> le PSK porte la meme limite, par condition EXPLICITE
    laravel/lang/fr/superv.php:62
      « Laisser vide conserve la cle deja enregistree. Ce portail ne la lit jamais. »

**L'écran legacy ne pouvait pas effacer le jeton non plus.** *La capacité n'est atteignable que par une
requête forgée envoyant explicitement une chaîne vide — ce n'est pas une capacité, c'est un artefact.*
**Et le portage ANNONCE la règle à l'écran.**

> **Ma crainte était juste dans sa FORME — un correctif qui retire une capacité — et fausse dans son
> OBJET.** *Trois fois ce soir j'ai bloqué un correctif sur ce motif : deux fois j'avais raison, ici non.*
> **Le blocage coûte une mesure ; l'inverse coûte une capacité — et c'est pour ça qu'il reste le bon
> réflexe même quand il se trompe.**

## 4. ✅ État : préparée, non appliquée

    scratchpad/e-telegraf/telegraf-jeton-en-clair.patch
      `git apply --check` passe · `ast.parse` valide · arbre intact
      ecriture : le garde du PSK repris tel quel
      lecture  : server_decrypt_password en :494, avec POURQUOI les deux sont indissociables
      et le commentaire menteur remplace par ce que le code FAIT, pas par une promesse

**Le geste urgent reste le vôtre** : *un `SELECT` sur `supervision_config` en production, et une
**rotation** si un jeton y figure.* **Sur le banc : 0 ligne.**
