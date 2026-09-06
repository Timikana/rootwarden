# DOSSIER-38 — cinq décisions éteignent le legacy, et il n'en reste aucune autre

**Session DSI. Mesuré le 2026-09-06 à 20:05 CEST**, après l'archivage du bloc 2
(`c29c3b3`). Banc libre, fenêtre accordée puis rendue.

**Réponse à la question posée : oui, il reste du legacy — 27 fichiers servis.
Mais il ne reste AUCUN travail de portage.** *Ce qui reste est bloqué par cinq
arbitrages, et les cinq sont les vôtres.*

---

## ① LES CINQ, ET CE QU'ELLES RETIENNENT

| arbitrage | page retenue | pourquoi |
|---|---|---|
| **I5** | `iptables/index.php` | le port SSH pour `iptables-restore` |
| **K4** | `ssh/index.php` | `NOPASSWD: ALL` |
| **S7b** | `security/index.php` | le scan qui ABOUTIT — **il envoie un courriel RÉEL** |
| **bashrc** | `bashrc/index.php` | `deploy` · `restore` · `prerequisites` |
| **fail2ban** | `fail2ban/index.php` | `install` · `restart` |

**Les cinq pages ont une route équivalente dans le portage. Ce ne sont pas les
PAGES qui manquent, ce sont cinq GESTES.**

### ⚠ ⑴.1 Les deux dernières viennent d'être mesurées, et elles n'étaient pas connues

**`bashrc` et `fail2ban` PARAISSAIENT portées** — `/bashrc` et `/fail2ban`
existent comme routes du portail. *C'est exactement l'erreur que la liste des
onze portables faisait : inventorier des ENTRÉES DE MENU et les lire comme un
inventaire de GESTES.*

**Leurs pages PHP n'écrivent rien** : tout passe par leur JavaScript. *Apparié
contre ce que le JS APPELLE, ancrage tolérant au préfixe de passerelle :*

```
bashrc     5 gestes    2 portés    3 ABSENTS
fail2ban  16 gestes   14 portés    2 ABSENTS
TEMOIN  /fail2ban/zzz-inexistant   0

/bashrc/prerequisites   POST — « Installe figlet si manquant »
/bashrc/deploy          écrit sur une machine distante
/bashrc/restore         idem
/fail2ban/install       nommé dans vos interdits
/fail2ban/restart       nommé dans vos interdits
```

> **Les cinq gestes absents touchent tous une MACHINE.** *Aucun n'est un oubli de
> portage : ce sont des gestes qu'on ne pose pas sans votre mot.*

---

## ② CE QUI A ÉTÉ ARCHIVÉ AUJOURD'HUI, ET SON CONTRÔLE

```
profile.php   mot de passe · courriel · clé SSH · sessions · export RGPD   5/5 portés
privacy.php   effacement de son compte                                     1/1 porté
TEMOIN  /profil/zzz-inexistant                                             0

au réseau :  /profile.php 302 -> 404   ·   /privacy.php 302 -> 404
             TEMOIN archivé  /adm/admin_page.php  404 inchangé
             TEMOIN vivant   /auth/login.php      200 inchangé
```

**Un écart inscrit AVANT l'archivage, parce qu'il ne se retrouverait plus
après** : *`privacy.php` supprimait la ligne `temporary_permissions` du compte ;
`Comptes::anonymise()` ne la nettoie pas.* **Le portage nettoie en revanche
`password_history` et `notification_preferences`, que le legacy laissait.**

*Et la différence de geste est délibérée : le legacy SUPPRIME la ligne `users`,
le portage l'ANONYMISE — pour préserver la chaîne d'audit de `user_logs`
(PARITE E-116, E-117).*

---

## ③ ⚠ L'ORDRE DU PROMPT DE MISSION ÉTAIT FAUX — et c'est moi qui l'avais écrit

**Il plaçait le bloc `auth/` EN PREMIER comme « archivable maintenant ».**

```
auth/verify.php     chargé par 10 fichiers
auth/functions.php  chargé par  5
auth/password_policy.php     par  3
```

> **Parmi ces dix : `api_proxy.php`, et LES TROIS PAGES QUE VOS ARBITRAGES
> PROTÈGENT.** *Archiver `auth/` en premier aurait défait trois de vos
> décisions.*

**`auth/` part en DERNIER.** *Mesure faite avant tout geste ; aucun fichier n'a
été déplacé sur la foi du prompt.*

---

## ④ ⛔ CE QUE MON INSTRUMENT NE VOIT PAS — dit avant qu'on s'y fie

**Mon graphe de dépendances mesure les `require`/`include` PHP. Il en manque
deux autres espèces, et je ne les ai PAS mesurées :**

| espèce | exemple | conséquence |
|---|---|---|
| **appel HTTP depuis le JS** | les pages retenues appellent `api_proxy.php` par leur JavaScript | `api_proxy.php` PARAÎT être une feuille et ne l'est pas |
| **le flux d'authentification** | on se connecte à `iptables/index.php` par `auth/login.php` | archiver la page de connexion laisserait des pages où l'on ne peut plus entrer |

> **Un compte de « fichiers archivables » fondé sur le seul graphe PHP
> SURESTIME.** *Je ne le publie donc pas.*

⚠ **Et une donnée de la session 7 qui va dans le même sens** : **47 de ses suites
passent par `api_proxy.php`** — c'est le chemin des suites legacy vers le
backend. *L'archiver emporterait la moitié legacy du banc, pas seulement des
pages.*

---

## ⑤ CE QUI VOUS REVIENT — et il n'y a rien d'autre

**Cinq décisions. Chacune libère sa page ; les cinq ensemble libèrent le socle,
`auth/`, la passerelle et la page de sortie.**

⚠ **Trois d'entre elles portent un geste à effet SORTANT ou DESTRUCTEUR** —
`S7b` envoie un courriel réel, `K4` écrit en root sur le parc, `I5` peut fermer
un accès SSH. *Ce ne sont pas des formalités d'archivage : ce sont les décisions
que ce chantier vous a réservées depuis le début.*

**Rien d'autre n'attend une décision produit.** *Les capacités portables l'ont
toutes été ; le tri des 22 routes est clos ; la dernière capacité portable —
le retrait d'UNE clé SSH précise — a été livrée aujourd'hui (`7f2c736`).*

**Les deux autres décisions ouvertes, indépendantes de l'extinction** :
`DOSSIER-37 §①` la sonde de vie faussement saine · `DOSSIER-36 §8-9` E-453.
