<?php

namespace App\Services;

use App\Support\RoutesBackend;

/**
 * Ce que LA PASSERELLE autorise — derive, jamais recopie.
 *
 * ══ POURQUOI CE SERVICE EXISTE, ET CE QU'IL REMPLACE ═════════════════════
 *
 * `legacy/api/docs.php` est une coquille Swagger de 40 lignes qui sert
 * `openapi.yaml` : **un fichier statique de 91 Ko, date du 2026-08-20, que rien
 * ne regenere.** Mesure du 2026-08-28 : 146 chemins declares contre 203 routes
 * reelles ; apres normalisation des parametres de chemin, 139 justes, **7
 * inexistants** et **64 routes non documentees**.
 *
 * Les 7 inexistants ont un seul motif : la spec declare le module d'audit SSH
 * sous DEUX separateurs — `/ssh_audit/…` (souligne, 404) et `/ssh-audit/…`
 * (tiret, servi). `/ssh_audit/fleet` et `/ssh-audit/fleet` y figurent tous deux :
 * une meme route, deux orthographes, une fausse.
 *
 * **Porter ce fichier n'aurait pas ete de la fidelite, mais la recopie d'un
 * cache.** Un portage fidele reproduit un COMPORTEMENT contradictoire et le
 * nomme ; un artefact fige que rien ne met a jour n'est pas un comportement. Et
 * vingt-six routes ont change de garde le 2026-08-27 seul : aucun document fige
 * ne peut suivre ce rythme, seul un document DERIVE peut.
 *
 * ══ TROIS COUCHES, ET CE SERVICE N'EN DERIVE QU'UNE ══════════════════════
 *
 *   1. la garde de la PAGE — `role:N` + `perm:xxx` sur la route du portage ;
 *   2. la PASSERELLE — liste blanche, reserve a l'administration,
 *      re-authentification. **La seule que ce service derive**, parce qu'elle
 *      vit ici, en code ;
 *   3. les DECORATEURS du backend.
 *
 * **La couche 3 n'est pas visible depuis le portage** : le conteneur ne monte
 * pas `backend/`. Ce service ne l'affirme donc PAS. L'embarquer en copie
 * recreerait le cache qu'on vient de retirer — et le relevé qui la mesure dit
 * lui-meme decrire **l'arbre de travail, pas le service**, faute de
 * redemarrage : cinq groupes de routes y portent DEUX etats.
 *
 * *Une page qui melange les trois couches refait le defaut qu'elle documente.*
 *
 * ══ CHAQUE LISTE EST ENUMEREE DEPUIS SA SOURCE, JAMAIS CROISEE ═══════════
 *
 * Mon premier jet parcourait la liste blanche en posant, pour chaque entree,
 * « est-elle reservee ? en flux ? exige-t-elle une re-authentification ? ».
 * **Les nombres m'ont alerte** : `step_up` rendait 0 alors que deux motifs
 * existent, et `flux` rendait 3 pour sept chemins.
 *
 * La cause : `correspond()` compare par SEGMENT, et 15 des 66 entrees sont des
 * ESPACES DE NOMS. `/supervision/` autorise `/supervision/zabbix/deploy` sans
 * etre elle-meme un flux ; `/policy/` autorise `/policy/sudo/deploy` sans
 * exiger elle-meme une re-authentification. Interroger l'ENTREE au lieu du
 * CHEMIN rendait donc « aucune route n'exige de re-authentification » — faux, et
 * du cote rassurant.
 *
 * Chaque liste est donc rendue **telle qu'elle est**, depuis sa propre source.
 * Aucun produit croise : un tableau qui pretend resumer trois listes sur la cle
 * de la premiere ment sur les deux autres.
 */
final class AutorisationsPasserelle
{
    /**
     * La liste blanche, avec la PORTEE de chaque entree.
     *
     * La forme du dernier caractere est une information, pas un detail : une
     * entree finissant par `/`, `_` ou `-` est un espace de noms — tout ce qui
     * commence par cette chaine passe. Un lecteur ne le devine pas.
     *
     * @return list<array{motif:string,espace:bool}>
     */
    public function listeBlanche(): array
    {
        return array_map(
            fn (string $m) => ['motif' => $m, 'espace' => $this->estEspace($m)],
            RoutesBackend::LISTE_BLANCHE,
        );
    }

    /**
     * La reserve a l'administration, et si une entree de liste blanche la couvre.
     *
     * `couverte` a faux signale une entree qui ne resserre RIEN : elle donne a
     * lire une protection sans objet. Le nombre est CALCULE et vaut zero
     * aujourd'hui — ce qui s'enonce plutot que se masque.
     *
     * @return list<array{motif:string,couverte:bool}>
     */
    public function reserveAdmin(): array
    {
        return array_map(
            fn (string $m) => ['motif' => $m, 'couverte' => RoutesBackend::autorisee($m)],
            RoutesBackend::ADMIN_SEULEMENT,
        );
    }

    /**
     * Les chemins relayes MORCEAU PAR MORCEAU, et l'entree qui les autorise.
     *
     * Quatre des sept ne sont PAS des entrees de liste blanche : ils passent par
     * l'espace de noms `/supervision/`. C'est pour cette raison que cette liste
     * s'enumere depuis `EN_FLUX` et non depuis la liste blanche.
     *
     * @return list<array{chemin:string,autorise:bool}>
     */
    public function flux(): array
    {
        return array_map(
            fn (string $c) => ['chemin' => $c, 'autorise' => RoutesBackend::autorisee($c)],
            RoutesBackend::EN_FLUX,
        );
    }

    /**
     * Les motifs exigeant une re-authentification ponctuelle.
     *
     * Ce sont des EXPRESSIONS, pas des chemins : `#^/policy/(sudo|sftp)/(deploy|remove)$#`
     * s'applique a quatre chemins concrets et a aucun autre. Les rendre comme
     * une liste de chemins inventerait une precision que la source n'a pas ; les
     * omettre laisserait croire qu'aucune route n'en exige.
     *
     * @return list<string>
     */
    public function motifsReauthentification(): array
    {
        return RoutesBackend::MOTIFS_STEP_UP;
    }

    /** Les compteurs, chacun sur SA source. */
    public function compteurs(): array
    {
        $blanche = $this->listeBlanche();

        return [
            'liste_blanche' => count($blanche),
            'espaces'       => count(array_filter($blanche, fn ($e) => $e['espace'])),
            'admin'         => count(RoutesBackend::ADMIN_SEULEMENT),
            'admin_orphelines' => count(array_filter($this->reserveAdmin(), fn ($e) => ! $e['couverte'])),
            'flux'          => count(RoutesBackend::EN_FLUX),
            'flux_hors_liste' => count(array_filter($this->flux(), fn ($e) => ! $e['autorise'])),
            'motifs_reauth' => count(RoutesBackend::MOTIFS_STEP_UP),
        ];
    }

    private function estEspace(string $motif): bool
    {
        $dernier = substr($motif, -1);

        return $dernier === '/' || $dernier === '_' || $dernier === '-';
    }
}
