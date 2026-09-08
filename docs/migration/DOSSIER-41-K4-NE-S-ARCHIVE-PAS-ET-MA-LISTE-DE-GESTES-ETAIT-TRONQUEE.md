# DOSSIER-41 — `ssh/` ne s'archive pas, et ma liste de gestes de `security/` était TRONQUÉE

**Session DSI. 2026-09-07, 20:2x CEST.** *Deux arbitrages demandés, UN rendu.*

---

## ① `ssh/index.php` — **DÉCISION : NE S'ARCHIVE PAS. `/deploy` est à PORTER.**

**Mesure de la session 4f (`eea588d`, outil `scripts/geste-porte.py` avec son jeu
de témoins), vérifiée ici.**

```
legacy/ssh/js/main.js appelle TROIS chemins de passerelle
  /preflight_check   PORTÉ   (K2, 2026-08-21)
  /logs              PORTÉ   (K3, 2026-08-21)
  /deploy            ABSENT  <- K4, et le seul
```

### ⚠ Le critère est REMPLI DANS L'AUTRE SENS, et je décide contre

**Les garde-fous de ce geste ne sont PAS dans la route.** *Vérifié :*

```
la route   backend/routes/ssh.py, /deploy, 141 lignes
           sauvegarde 0 · à-blanc 0 · un seul `subprocess.Popen`
           3 `check_machine_access` — un contrôle d'ACCÈS, pas un filet

le script  backend/configure_servers.py, 1248 lignes
           `_absence_verifiee` ×3   (vérifie l'EFFET, pas la commande)
           `visudo -cf` ×8          argparse ×3   `__main__` ×1
           -> il a un CLI, et il SURVIT à la mort du legacy
```

*(non vérifié : les drapeaux `--machines` et `--workers` — `ugrep` les a pris
pour ses propres options.)*

> **Donc archiver ne perdrait aucun garde-fou.** *C'est la structure du cas
> `fail2ban`, pas celle de `bashrc/deploy`.*

**ET JE DÉCIDE POURTANT DE NE PAS ARCHIVER.** *Le critère « où vit la valeur »
suffit à trancher une enveloppe de 26 lignes ; il ne suffit pas ici.*

> **Ce geste est le produit.** *RootWarden déploie des clés SSH. Réduire son
> geste central à « se connecter au serveur et lancer un script python avec des
> identifiants de machines » n'est pas une v2.0 : c'est une v2.0 qui a perdu sa
> raison d'être.*

**La session 4f le dit dans les mêmes termes et me laisse la décision** :
*« pour le geste le plus conséquent du produit, c'est un vrai recul
d'ergonomie ; que ce recul soit acceptable est un arbitrage produit, pas une
mesure ».* **Il ne l'est pas.**

⛔ **Et le portage reste bloqué sur VOTRE arbitrage `NOPASSWD: ALL`** — celui-là
est le vôtre et je ne le touche pas. *Ma décision porte sur « faut-il le
garder », pas sur « peut-on le porter aujourd'hui ».*

### ⚠ Une correction que la session 4f m'a transmise, puis retirée

*Elle m'avait écrit que le paragraphe « POURQUOI `role(2)` ET PAS
`@require_permission` » appartenait à `stream_logs`.* **Il appartient à
`/deploy`** — ligne 422, dans un corps qui va de 398 à 534. *Elle avait ancré sur
le `def` qui SUIT au lieu du `def` PROPRIÉTAIRE.* **C'est donc la justification
écrite de la garde de K4 elle-même.**

---

## ② `security/index.php` — ⛔ **JE NE TRANCHE PAS : MA LISTE ÉTAIT FAUSSE**

**J'ai demandé à la session 5f de croiser SEPT gestes par TABLE. Elle l'a fait,
proprement, et six sont portés.** *Puis j'ai mesuré ma propre liste :*

```
les 10 "gestes" que j'ai transmis contiennent  /cve_        <- une TRONCATURE
/cve_scan et /cve_scan_all NE FIGURENT PAS dans ma liste
```

**Le JS construit ses chemins avec une variable À L'INTÉRIEUR** —
`` `${API_URL}/cve_${action}` `` — *et mon extraction s'arrête au `${`.*

> **S7b — le scan qui ABOUTIT et envoie un courriel réel — est caché derrière
> cette troncature.** *La session 5f a mesuré exactement ce que je lui ai donné,
> et ce que je lui ai donné était incomplet.*

⚠ **NEUVIÈME instance de la même famille chez moi**, et une variante neuve : les
huit précédentes portaient sur ce qui PRÉCÈDE le chemin (délimiteur, `}`,
préfixe de passerelle) ou sur la forme de l'appel SQL. **Celle-ci porte sur une
variable AU MILIEU du chemin.**

### Ce que la mesure de 5f établit quand même, et qui reste acquis

| geste | verdict |
|---|---|
| `/cron_preview` · `/cve_results` · `/cve_remediation` · `/cve_schedules` | **PORTÉS** |
| `/cve_compare` | **PORTÉ mais RÉTRÉCI** — comparer deux scans ARBITRAIRES n'existe plus, la signature ne prend que `machineId` |
| `/cve_whitelist` (GET/POST/**DELETE**) | **capacité SANS INTERFACE** — non réimplémentée, aucun écran, mais atteignable par le préfixe `/cve_` de la liste blanche |

**Et sa rectification vaut d'être gardée** : *elle avait commité « NON PORTÉ »
pour `/cve_whitelist`, puis mesuré que la passerelle l'autorise.* **« Non porté »
dit *capacité perdue* ; la mesure dit *capacité sans interface*. Ce n'est pas la
même décision.**

⚠ **`cve_whitelist` a ZÉRO ligne en base.** *Trois de ses sept colonnes —
`reason`, `whitelisted_by`, `expires_at` — n'existent que pour rendre l'oubli
impossible.* **Un garde-fou jamais employé ne protège de rien, et c'est le fait
qui pèse contre lui.**

---

## ③ CE QUI VOUS REVIENT

| | |
|---|---|
| **`NOPASSWD: ALL`** | débloque le portage de `/deploy`. **Le seul verrou de `ssh/`.** |
| **les quatre gestes `iptables`** | `DOSSIER-40`, décidé : à porter |
| `/cve_compare` rétréci | régression d'une capacité PORTÉE — à restaurer ou à assumer |
| `/cve_whitelist` | trois voies : lui rendre un écran · la retirer de la liste blanche · la laisser orpheline |

⛔ **Rien n'a été porté ni exercé.** *Votre carte blanche couvre les décisions et
la publication ; elle ne transmet pas un périmètre tenu de vous, et je ne peux
pas l'accorder à un pair.*

**NON MESURÉ, et c'est ma part** : la liste complète des gestes de `security/`.
*Je la reprends avec une extraction qui voit les variables internes avant de
demander quoi que ce soit à quiconque.*
