# AUDIT — la chasse aux « cases cochées » : la méthode, son témoin, et son angle mort

**Session 5 (sécurité, lecture seule).** Relevé du **2026-09-05, 23:46 CEST**.
`docs/` seul, fenêtre 3 du LOT.

**Je ne publie PAS de compte de trous.** *Ma méthode en rend 53 ; elle en
sur-déclare une majorité, et je peux dire pourquoi.* **Ce que je livre : la
réponse de PROVENANCE, une méthode qui passe son témoin, et son angle mort
mesuré.**

---

## 1. ⚠ LA PROVENANCE — et elle explique le mécanisme, pas seulement les cas

Le DSI demande de poser la question de la **fabrication** avant celle du contenu.
**Elle se lit dans le format même des déclarations :**

```
I1 PORTÉ `3c3fe98`  — la consultation        F1 PORTÉ `v1.38.0`
I2 PORTÉ `f183f07`  — la copie en base       F2 PORTÉ `v1.38.2`
I3 PORTÉ `ef32870`  — l'historique           B3 PORTÉS  `v1.…`
I4 PORTÉ `c42fe48`  — la validation à blanc  G1 PORTÉ   `v1.…`
```

**Chaque déclaration cite un COMMIT ou une VERSION.** *Elle enregistre qu'un
commit a atterri — **pas** qu'un périmètre est complet.*

> **Le périmètre d'un sous-lot vit AILLEURS que sa déclaration de portage** : il
> est défini dans le découpage du module, souvent des jours plus tôt, par une
> autre session. **Et rien ne confronte les deux à la livraison.**

### 1.1 J'en ai la preuve de première main, et elle me met en cause

**C'est moi qui ai écrit le découpage A1–A4 de `ssh_audit`** — et mon §5 range
`/trends` **dans le périmètre d'A1**. A1 a ensuite été déclaré porté, en citant
un commit. **`/ssh-audit/trends` n'a jamais été câblé.**

> **Le trou est dans un sous-lot dont j'ai défini le périmètre, déclaré porté par
> quelqu'un qui citait un commit — et personne n'a repris ma liste item par item
> au moment de livrer.** *Ce n'est pas une négligence : c'est qu'aucun geste du
> processus ne le demande.*

**Prédiction que ça permet** : les trous ne sont pas répartis au hasard. **Ils
sont là où un découpage a énoncé un périmètre ET où un commit ultérieur a déclaré
le lot porté.** *Les modules sans découpage écrit n'ont pas ce mécanisme — ils en
ont d'autres.*

---

## 2. La méthode, et elle passe son témoin

**Pour chaque route du backend, existe-t-il un appelant dans le portage ?**
Commentaires retirés (JS, Blade), aucune troncature, chemins composés rattrapés
par préfixe.

```
routes backend                       203
fragments d'appel relevés            262
routes SANS appelant                  53
```

**Témoin positif, posé AVANT de conclure** — les deux trous connus :

| témoin | résultat |
|---|---|
| `/ssh-audit/backups` | **TROUVÉ** |
| `/ssh-audit/trends` | **TROUVÉ** |

*Sans eux, « 53 » aurait pu être « ma sonde ne lit pas les appels ».*

---

## 3. ⛔ ET SON ANGLE MORT — mesuré, ce qui m'interdit de publier 53

**Ma méthode ne détecte qu'UNE des cinq formes** : *« le portage APPELLE la route
backend »*. **Elle est aveugle à la forme n°4 — le portage RÉIMPLÉMENTE la
capacité en Laravel.**

**Mesuré sur `cve` :**

```
laravel/app/Services/PlanificationsCve.php   DB::table × 7   passerelle × 0
laravel/app/Services/ScansCve.php            DB::table × 6   passerelle × 2
laravel/app/Services/SuiviCve.php            DB::table × 5   passerelle × 2
```

**Le portage lit la base directement.** *Les 14 routes `/cve_*` sans appelant ne
sont donc pas des trous : la capacité est portée par une autre couche.*

> **Publier « 53 trous » serait l'erreur du côté qui ALARME**, celle que ce
> chantier corrige depuis deux jours. **Ce sont 53 CANDIDATS**, et ils tombent
> dans **quatre** catégories que la méthode ne distingue pas :

| catégorie | exemples | ce que ça demande |
|---|---|---|
| **réimplémenté en Laravel** (forme 4) | les 14 `/cve_*` | **rien** — faux positif de ma sonde |
| **retenu par arbitrage** | `/iptables-apply|restore|rollback` (I5) · `/ssh-audit/fix|reload|restore|save-config|toggle` (A3) · `/ssh-audit/scan-all` · `/cve_scan*` | **décider** |
| **orphelin par dépréciation** | `/policy/rollback|deployments|list` | **arbitrer ce qu'on garde** |
| **trou dans un sous-lot déclaré complet** | `/ssh-audit/backups` (A2) · `/ssh-audit/trends` (A1) | **finir, et corriger la déclaration** |

**Seule la quatrième est une « case cochée ».** *Et je n'en ai confirmé que deux
— les deux que le DSI m'a données comme témoins.*

---

## 4. Ce qu'il faudrait pour rendre un compte honnête

**Trier les 53 route par route** exige, pour chacune : *le portage
réimplémente-t-il la capacité ailleurs ?* — **et c'est de la lecture, pas du
motif.** *Ma sonde peut réduire l'espace de 203 à 53 ; elle ne peut pas trancher
les 53.*

**Ce qui rendrait la méthode complète** : détecter la forme 4 en croisant les
**tables** écrites/lues, et non les chemins. *Une capacité réimplémentée touche
la même table que la route qu'elle remplace.* **Non fait — et c'est un vrai
travail, pas un ajustement.**

---

## 5. Non mesuré, et dit

- **je n'ai pas trié les 53** : je livre la méthode, son témoin, son angle mort
  et la ventilation en quatre catégories — *pas un verdict par route* ;
- **la ventilation ci-dessus est fondée sur mes relevés antérieurs** (`iptables`,
  `security`, `ssh_audit`, `politiques`), pas sur une mesure neuve des 53. *Les
  catégories des modules que je n'ai pas audités — `admin`, `updates`, `ssh`,
  `monitoring` — sont **non tranchées**, et ce sont 23 des 53.*
- **aucune écriture hors `docs/`, aucun geste exercé.**
