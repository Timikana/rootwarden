# DOSSIER-51 — L'extinction est prête sur la moitié que j'ai mesurée, et je nomme l'autre

**Écrit le 2026-09-08, ~05:0x.** *Mesuré au RÉSEAU, pas dans l'arbre — c'est la faute que
j'ai payée une heure plus tôt en annonçant à l'exploitant un geste qu'il avait déjà fait.*

---

## ① LE LEGACY N'A QUE TROIS ÉCRANS RÉELS

**Et le trouver a demandé de corriger ma propre mesure.** Mon premier relevé lisait le code
HTTP seul :

```
/auth/step_up.php   200   -> « le legacy sert une page que le portage rend en 405 »
```

**J'allais publier un écart qui n'existe pas.** Le corps fait **un octet**.

> ⛔ **Un code 200 n'est pas un contenu.** *Un `include` interrogé directement rend 200 et
> rien — indiscernable d'une page, pour qui ne lit que le statut.*

**Cinquième fausse alarme écartée cette nuit avant publication**, et la première qui portait
sur une mesure au réseau — donc sur l'instrument que je venais de déclarer le plus fiable.

### Le relevé refait, avec la taille du corps

```
LEGACY :8446                  code   octets
/auth/login.php                200    4865   PAGE
/auth/forgot_password.php      200    3050   PAGE
/auth/reset_password.php       200    2247   PAGE
/_sortie.php                   200    1336   PAGE — l'ErrorDocument DU VHOST
/auth/verify.php               200       1   include, jamais une page
/auth/step_up.php              200       1   include, jamais une page
/iptables/                     302       1   garde -> connexion
/api_proxy.php                 302       1   garde -> connexion
/adm/api/notifications.php     302       1   garde -> connexion
```

```
PORTAGE :8443                 code   octets
/connexion                     200    3827   ✅ remplace login.php
/mot-de-passe-oublie           200    2387   ✅ remplace forgot_password.php
/reinitialiser                 200    1764   ✅ remplace reset_password.php
/second-facteur                302     375   redirige faute de 2FA en attente — correct
temoin- /zzz-inexistant        404           l'instrument discrimine
```

> **Trois écrans réels sur le legacy, trois servis par le portage. `_sortie.php` est le
> document 404 du vhost lui-même : il part avec lui, il ne se porte pas.**

---

## ⛔ ② ET VOICI CE QUE JE N'AI PAS MESURÉ — LA MOITIÉ QUI COMPTE AUTANT

**Toutes mes requêtes sont NON AUTHENTIFIÉES.** Les trois `302` disent « va te connecter » ;
**ils ne disent rien de ce que ces chemins rendent à une session ouverte.**

```
mesure       la surface ATTEIGNABLE SANS S'AUTHENTIFIER
non mesure   ce que le legacy rend a une session ouverte
```

*Pour la surface authentifiée, ce que j'ai est une lecture de CODE — les cinq gestes du
pare-feu comptés dans `pare-feu.js`, et la moitié serveur du retour arrière éprouvée par
sept assertions avec table intacte.* **C'est solide et ce n'est pas la même chose.**

⛔ **Et la vérification au réseau de la moitié authentifiée est BLOQUÉE, pas oubliée** :

```
swap 3602/3702 (97,3 %) · disponible 1,4 Gio
Chrome : « Timed out waiting for the WS endpoint », deux fois, chez une autre session
```

> **Une suite lancée maintenant échouerait pour la machine et pas pour son objet — un rouge
> dont la cause n'est pas celle qu'on cherche.** *C'est la raison pour laquelle je ne comble
> pas ce trou par un essai qui n'en serait pas un.*

---

## ③ CE QUE L'EXTINCTION DEMANDE, ET LA LISTE EST COURTE

```
FAIT et mesure
  l'echange des ports              applique le 2026-09-07 a 19:39, verifie au reseau
  les 3 ecrans d'auth              portes et servis
  les 5 gestes du pare-feu         portes (validate · apply · rollback · lecture)
  les 11 racines                   aucune capacite qui ne soit ailleurs

RESTE, et rien n'est de moi
  1  ⛔ LA MEMOIRE           swap a 97 % : personne ne peut mesurer a l'ecran
  2  la moitie navigateur    du retour arriere et du panneau de recherche
  3  le panneau `suite`      il annonce encore le retour arriere « ailleurs » ;
                             la session refuse d'ecrire « tout est porte » sans
                             l'avoir VU, et c'est exactement ce que ce panneau
                             existe pour eviter
  4  restart python          E-460 (GEOIP) + E-461 (fragments)
  5  MAIL_MAILER=smtp        etape ⑤ du DOSSIER-48
  6  les 2 decisions du DOSSIER-49
```

**L'ordre n'est pas indifférent : ① débloque ②, ② débloque ③, et ③ est la dernière phrase
que le produit dit de lui-même avant qu'on éteigne.**

> **Le legacy ne tient plus par une capacité. Il tient par une phrase qu'on refuse d'écrire
> sans l'avoir vue, et par 100 Mio de mémoire.**

---

## ④ TROIS CHOSES APPRISES SUR LES INSTRUMENTS, ET ELLES SE RESSEMBLENT

**Toutes de la même forme : l'instrument était juste, son CHAMP était trop étroit.**

```
--rw-part-unban        cherche la definition dans la FEUILLE ; elle est posee par
                       la PAGE VIVANTE (`setProperty`), avec `var(x, repli)`
/auth/step_up.php      lu le STATUT ; le sens etait dans la TAILLE DU CORPS
/policy/sudo/rollback  demande « ce CHEMIN est-il appele » ; la question etait
   (releve par un pair) « cette CAPACITE est-elle portee » — le chemin n'existait
                       pas, et un seul `/policy/rollback` sert les deux appels
```

*Dans les trois cas la sonde a rendu une réponse cohérente à une question qui n'était pas
celle qu'on posait.* **Et dans les trois cas ce qui a arrêté la publication n'était pas la
mémoire d'une règle** — c'était **un reste inexpliqué** : un jeton manquant sur une frise qui
s'affiche, un 200 sur un fichier qui n'est pas une page, deux `ABSENT` sur des gestes que la
page offre visiblement.

> **Une règle écrite ne protège pas son auteur. Ce qui protège, c'est un chiffre qui ne se
> referme pas.** *(formulation d'un pair, qui a commis six heures après l'avoir écrite la
> règle qu'il m'avait documentée)*

**C'est l'argument le plus fort en faveur des témoins DANS le rapport plutôt qu'en interne :**
un témoin interne valide l'instrument ; un témoin imprimé **donne au lecteur de quoi voir un
reste.**
