# DOSSIER-60 — L'avertissement de l'étape 1 me décrit, et je tranche

**Mesuré le 2026-09-08 entre 18:40 et 19:00 CEST.** Aucun geste exercé.

> La mission dit : *« Si le rapport doc/code dépasse 2 pour 1, le dire et
> l'attaquer : l'équipe écrit sur ses propres mesures au lieu de porter. »*
> **Cinq tours de suite à ZÉRO code, quatre révisions d'un seul compte, et cinq
> des dix derniers commits sont les miens. L'avertissement ne décrit pas
> l'équipe : il me décrit.**

---

## 1. L'item ① de la file, remesuré et non cité

La mission demande d'apparier les catalogues **contre ce que leur JS APPELLE**.
Je l'ai refait ce soir, de zéro, au lieu de renvoyer à `E-501`.

```
fichiers JS du portage                     42
chemins litteraux appeles                  58   ->  49 backend · 8 Laravel · 1 passerelle
chemins a suffixe CONCATENE                23   ->  15 Laravel · 6 backend · 2 a examiner
                                          ────
ORPHELINS, litteraux et concatenes         0

TEMOINS  /fail2ban/status -> backend ✅   /connexion -> Laravel ✅
         /zzz-inexistant  -> aucun    ✅   /comptes/${id}/deverrouiller -> apparie ✅
         /zzz/${x}/inexistant -> aucun ✅
```

**Les 23 concaténés sont comptés à part et examinés**, pas tronqués : *un relevé
qui perd le suffixe d'une concaténation ment.* Les deux derniers
(`/policy/sftp/` · `/policy/sudo/`) sont **couverts** —
`backend/routes/policies.py:176 :273 :302 :347 :423 :452` portent
`{deploy,audit,remove}` pour les deux familles, et le JS compose
`'/policy/sftp/' + geste` avec exactement ces valeurs.

⚠ **Et ces deux-là étaient ma cinquième fausse alarme du jour.** J'avais
substitué *« le préfixe littéral doit apparier une route »* à *« le chemin
composé atteint un répondant »*.

**L'item ① est donc satisfait, établi ce soir et non récité.**

---

## 2. ⛔ CINQ FAUSSES ALARMES EN UN JOUR, ET ELLES ONT LA MÊME FORME

| # | la propriété à mesurer | le substitut employé | l'erreur |
|---|---|---|---|
| ① | un `finally` gouverne-t-il la fermeture ? | la **présence** du mot `finally` | 55 dédouanés à tort |
| ② | la population des suites | `puppeteer.launch` **littéral** | 15 suites invisibles |
| ③ | une fermeture est-elle atteinte avant l'`exit` ? | la **position textuelle** | 40 accusés à tort |
| ④ | idem, chez le pair | l'**écart en lignes** (≤ 2, nombre magique) | 3 accusés à tort |
| ⑤ | le chemin composé atteint-il un répondant ? | le **préfixe littéral** | 2 accusés à tort |

> **Chacune a substitué un SUBSTITUT à la propriété. Un substitut se trompe
> toujours dans le même sens, et il est stable : il ne se signale pas.**
> (formulation de `gestion-ssh-key-c6`)

⚠ **Et la raison pour laquelle les substituts de proximité accusent : ils
échouent quand le code est AÉRÉ — et le code aéré est le code soigné.** *Nos
instruments accusaient donc préférentiellement les fichiers les mieux écrits.*

---

## 3. Ce que je tranche — E-514

**L'étape 2 de la mission est sans objet, établi par trois voies indépendantes :**

```
① item par item                E-501
② le script d'extinction       six fois « deja archivee », exit 0   (E-508)
③ les sites d'APPEL du JS      0 orphelin sur 81 chemins            (ce soir)
```

**Et l'étape 1 mesure une pathologie qui est la mienne.** Le seul défaut réel
qui reste — `(a)`, 67 suites dont la fermeture n'est gouvernée par aucun
`finally` — est de l'**outillage de test**, il ne compte pas comme CODE au sens
de la mission, et son adoption est bloquée sur `E2E_TOTP_SECRET`, absent de
l'environnement et de `srv-docker.env`.

> **Je cesse de relancer la boucle.** *Continuer produirait exactement ce que
> l'étape 1 décrit : un tour de plus à mesurer mes propres mesures. Quatre
> révisions d'un compte en une soirée, cinq fausses alarmes, et un défaut (b)
> qui n'a jamais existé — c'est le rendement d'un dispositif qui n'a plus
> d'objet, pas d'un manque de rigueur.*

**Ce qui garde de la valeur, et ce n'est pas rien** : les instruments livrés
(`withNavigateur`, son épreuve au processus, le cliquet à dix contrôles)
**mordent maintenant sur les régressions futures** — la suite suivante est sûre
par défaut, et un receveur de `.close(` inconnu fait échouer le contrôle. *C'est
la seule forme de travail qui survive à un chantier fini.*

---

## 4. Ce qui revient à l'exploitant, inchangé et complet

```
① signer patch 07                      supprime le service php, emporte le faux
                                        UNHEALTHY (php unhealthy depuis 45 h)
② placer le numero de version          ORDRE NON COMMUTATIF : ecrire cote
                                        portage AVANT de basculer le montage
③ retirer le repertoire et le vhost    l'etape ⑥ dit « en dernier »
④ le garde du controle 1               scripts/eteindre-le-legacy.sh:102 —
                                        `git ls-files` sur un fichier .gitignore,
                                        donc il ne peut JAMAIS refuser
⑤ la carte des perimetres              qui tient scripts/ — ni 0b ni moi
⑥ SKILL.md:16                          « 63 tables », mesure 65 (hors
                                        autorisation recue)
⑦ le mot de passe OVH                  expose par moi, a changer
⑧ MAIL_MAILER / APP_URL                etapes 1-4 de srv-docker.env.example:90
⑨ la RAM                               5,8 Gio, swap plein a 120 Ki pres
```

**Rien de cette liste n'est à une session.** *Le produit, lui, est fini : `main`
verte, zéro `.php` métier hors archive, zéro chemin d'appel orphelin, 49
catalogues à parité stricte.*
