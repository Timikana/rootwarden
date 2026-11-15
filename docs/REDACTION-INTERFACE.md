# Rédiger les textes de l'interface

Les pages s'adressent à des administrateurs qui y reviennent souvent. Un lecteur
parcourt 20 à 28 % des mots d'une page ; chaque phrase de trop fait concurrence
à celle qui compte.

## Les règles

1. **Une page dit quoi faire, pas comment elle a été construite.** Jamais à
   l'écran :
   - l'historique (« depuis le correctif », « désormais », numéros de sous-lot) ;
   - les comparaisons avec l'ancien portail, qui n'est plus servi ;
   - les noms internes (colonne, drapeau, route, `UPDATE`, « le backend »), sauf
     si l'administrateur doit les taper.
2. **Phrases courtes** : 25 mots au plus. Introduction de page : une phrase.
3. **Aide sous un champ** seulement si le champ n'est pas évident : une phrase,
   qui dit le format ou la contrainte.
4. **Un avertissement sur l'action en cours reste visible**, jamais replié ni en
   infobulle. Une à deux phrases : ce qui se passe, ce qui est irréversible.
5. **Ce dont une minorité de visites a besoin se replie** (guide, limites
   techniques, cas rares) dans `<details class="rw-details">`, avec un
   `<summary>` qui dit ce qu'on va trouver. Un seul niveau de repli.
6. **Pas de majuscules d'insistance.** Le ton suffit ; au besoin, un `<strong>`.
7. **État vide** : ce qui manque, puis l'action à faire. Deux phrases au plus.
8. **Erreur** : ce qui s'est passé et quoi faire. Garder « ne relance pas »
   quand une seconde tentative peut doubler l'effet.
9. **Ne pas répéter** ce que la page dit déjà ailleurs.
10. **Un texte raccourci doit rester vrai** : revérifier dans le code chaque fait
    gardé. Un texte faux se corrige ou se supprime.
11. **Vouvoiement**, comme le reste du portail : « Rechargez la page », « Votre
    rôle ».

## Comment s'y prendre, page par page

1. Mesurer avant : mots d'aide par vue (`scripts/` ou la mesure du chantier).
2. Lire tous les textes de la page (`lang/fr/<module>.php`), les classer :
   **garder court**, **replier**, **supprimer**.
3. Réécrire FR et EN dans le même commit, mêmes clés. Supprimer partout une clé
   devenue inutile (catalogues, vue, contrôleur, script).
4. Ne jamais retirer un attribut `data-rw` sans mettre à jour les suites qui le
   lisent (`grep -rn 'data-rw="x"' tests/e2e laravel/tests`).
5. Mesurer après, lancer `php artisan test`, regarder la page.

## Sources

- GOV.UK, langage clair : https://guidance.publishing.service.gov.uk/writing-to-gov-uk-standards/writing-guidelines/clear-language/
- GOV.UK, aide de champ et `details` : https://design-system.service.gov.uk/components/text-input/ · https://design-system.service.gov.uk/components/details/
- NN/g, lecture et divulgation progressive : https://www.nngroup.com/articles/how-little-do-users-read/ · https://www.nngroup.com/articles/progressive-disclosure/
- NN/g, confirmations : https://www.nngroup.com/articles/confirmation-dialog/
- GitLab Pajamas, actions destructives : https://design.gitlab.com/patterns/destructive-actions
- Carbon, états vides et infobulles : https://carbondesignsystem.com/patterns/empty-states-pattern/ · https://carbondesignsystem.com/components/tooltip/usage/
