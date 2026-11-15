<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

/**
 * Les cles SSH PUBLIQUES d'un compte — plusieurs, chacune avec sa portee.
 *
 * ══ LE MODELE (migration 067) ══════════════════════════════════════════════
 *
 * Un compte n'avait qu'UNE cle (`users.ssh_key`), posee sur toutes ses
 * machines. Besoin d'exploitation : une cle personnelle valable partout, et des
 * cles dediees a UN serveur. D'ou :
 *
 *     user_ssh_keys           une ligne par cle, `toutes_machines` 0 ou 1
 *     user_ssh_key_machines   la portee d'une cle restreinte
 *
 * ⚠ LA PORTEE RESTREINT, ELLE N'OUVRE RIEN. Une cle n'est posee sur une
 * machine que si le compte y a acces (`user_machine_access`) ; restreindre une
 * cle a une machine sans acces ne donnerait rien. C'est pourquoi la portee ne
 * peut designer QUE des machines accessibles au compte.
 *
 * Ce service est le SEUL ecrivain des cles, comme `Comptes::definitCleSsh`
 * l'etait de l'ancienne colonne (E-115 : le legacy en avait trois).
 * `users.ssh_key` n'est plus ni lue ni ecrite — `ColonneSshKeyAbandonneeTest`
 * le garde.
 */
final class ClesPubliques
{
    public const LIBELLE_MAX = 100;

    /**
     * Valide la FORME d'une cle publique : algorithme dans la liste fermee, corps
     * en base64, commentaire libre, UNE ligne. Refuse tout ce qui precede
     * l'algorithme — c'est la que vivent les options d'`authorized_keys`
     * (`command=`, `from=`, `no-pty`), qui changent le sens de la ligne deployee.
     *
     * Regle remontee de `Comptes::verifieCleSsh`, qui y delegue : une seule regle.
     *
     * @return string|null la cle du message d'erreur, ou null si la forme est bonne
     */
    public static function verifieForme(string $cle): ?string
    {
        $cle = trim($cle);
        if ($cle === '') {
            return null;
        }
        if (str_contains($cle, "\n") || str_contains($cle, "\r")) {
            return 'comptes.err_cle_lignes';
        }
        $morceaux = preg_split('/\s+/', $cle);
        if (count($morceaux) < 2) {
            return 'comptes.err_cle_forme';
        }
        if (! in_array($morceaux[0], Comptes::ALGOS_SSH, true)) {
            return 'comptes.err_cle_algo';
        }
        if (preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $morceaux[1]) !== 1) {
            return 'comptes.err_cle_base64';
        }

        return null;
    }

    /**
     * Les cles du compte, avec leur portee.
     *
     * @return list<array{id:int, libelle:string, cle:string, empreinte:string, algo:string,
     *                    toutes_machines:bool, machines:list<array{id:int, name:string}>, created_at:string}>
     */
    public function duCompte(int $idCompte): array
    {
        $cles = DB::table('user_ssh_keys')->where('user_id', $idCompte)
            ->orderBy('created_at')->orderBy('id')->get();
        if ($cles->isEmpty()) {
            return [];
        }
        $portees = DB::table('user_ssh_key_machines as km')
            ->join('machines as m', 'm.id', '=', 'km.machine_id')
            ->whereIn('km.key_id', $cles->pluck('id')->all())
            ->orderBy('m.name')
            ->get(['km.key_id', 'm.id', 'm.name'])
            ->groupBy('key_id');

        return $cles->map(fn ($c) => [
            'id' => (int) $c->id,
            'libelle' => (string) $c->libelle,
            'cle' => (string) $c->cle,
            'empreinte' => self::empreinte((string) $c->cle),
            'algo' => (string) strtok((string) $c->cle, ' '),
            'toutes_machines' => (bool) $c->toutes_machines,
            'machines' => ($portees[$c->id] ?? collect())
                ->map(fn ($m) => ['id' => (int) $m->id, 'name' => (string) $m->name])->values()->all(),
            'created_at' => (string) $c->created_at,
        ])->values()->all();
    }

    /**
     * Les machines auxquelles le compte a acces — les seules qu'une portee peut designer.
     *
     * @return list<array{id:int, name:string}>
     */
    public function machinesAccessibles(int $idCompte): array
    {
        return DB::table('user_machine_access as a')
            ->join('machines as m', 'm.id', '=', 'a.machine_id')
            ->where('a.user_id', $idCompte)
            ->where(function ($q) {
                $q->whereNull('m.lifecycle_status')->orWhere('m.lifecycle_status', '<>', 'archived');
            })
            ->orderBy('m.name')
            ->get(['m.id', 'm.name'])
            ->map(fn ($m) => ['id' => (int) $m->id, 'name' => (string) $m->name])->all();
    }

    /**
     * Ajoute une cle. Rend la cle de traduction de l'erreur, ou null.
     *
     * @param  list<int|string>  $machines  ignore si `$toutes`
     */
    public function ajoute(int $idCompte, string $libelle, string $cle, bool $toutes, array $machines = []): ?string
    {
        $cle = trim($cle);
        $libelle = trim($libelle);
        if ($cle === '') {
            return 'profil.err_cle_vide';
        }
        if (($err = self::verifieForme($cle)) !== null) {
            return $err;
        }
        if ($libelle === '' || mb_strlen($libelle) > self::LIBELLE_MAX) {
            return 'profil.err_cle_libelle';
        }
        if ($this->dejaPresente($idCompte, $cle)) {
            return 'profil.err_cle_doublon';
        }

        $ids = [];
        if (! $toutes) {
            $ids = array_values(array_unique(array_map('intval', $machines)));
            if ($ids === []) {
                return 'profil.err_cle_portee_vide';
            }
            $accessibles = array_column($this->machinesAccessibles($idCompte), 'id');
            if (array_diff($ids, $accessibles) !== []) {
                // Une machine hors d'acces : refus ENTIER, pas un filtrage
                // silencieux qui poserait une portee differente de la demandee.
                return 'profil.err_cle_portee_hors_acces';
            }
        }

        DB::transaction(function () use ($idCompte, $libelle, $cle, $toutes, $ids): void {
            $id = DB::table('user_ssh_keys')->insertGetId([
                'user_id' => $idCompte,
                'libelle' => $libelle,
                'cle' => $cle,
                'toutes_machines' => $toutes ? 1 : 0,
                'created_at' => now(),
            ]);
            foreach ($ids as $machine) {
                DB::table('user_ssh_key_machines')->insert(['key_id' => $id, 'machine_id' => $machine]);
            }
        });

        return null;
    }

    /**
     * Retire une cle DU COMPTE. Rend false si elle n'existe pas ou appartient
     * a un autre compte : l'identifiant vient de la requete, le proprietaire de
     * la session, et les deux doivent concorder.
     */
    public function retire(int $idCompte, int $idCle): bool
    {
        return DB::table('user_ssh_keys')->where('id', $idCle)->where('user_id', $idCompte)->delete() === 1;
    }

    /**
     * Remplace TOUTES les cles du compte par une seule, valable partout — le
     * sens de l'ecriture administrative `POST comptes/{id}/cle-ssh` et de
     * l'import CSV, conserve tel quel. Une cle vide retire toutes les cles.
     */
    public function remplaceParUneSeule(int $idCompte, string $cle, string $libelle = 'cle principale'): ?string
    {
        $cle = trim($cle);
        if ($cle !== '' && ($err = self::verifieForme($cle)) !== null) {
            return $err;
        }
        DB::transaction(function () use ($idCompte, $cle, $libelle): void {
            DB::table('user_ssh_keys')->where('user_id', $idCompte)->delete();
            if ($cle !== '') {
                DB::table('user_ssh_keys')->insert([
                    'user_id' => $idCompte, 'libelle' => $libelle, 'cle' => $cle,
                    'toutes_machines' => 1, 'created_at' => now(),
                ]);
            }
        });

        return null;
    }

    /** Toutes les cles d'un compte partent avec lui (anonymisation). */
    public function retireTout(int $idCompte): void
    {
        DB::table('user_ssh_keys')->where('user_id', $idCompte)->delete();
    }

    /**
     * Empreinte SHA256 au format d'`ssh-keygen -lf` (base64 sans `=`).
     * Chaine vide si le corps n'est pas du base64.
     */
    public static function empreinte(string $cle): string
    {
        $corps = preg_split('/\s+/', trim($cle))[1] ?? '';
        $brut = base64_decode($corps, true);

        return $brut === false || $brut === '' ? '' : rtrim(base64_encode(hash('sha256', $brut, true)), '=');
    }

    private function dejaPresente(int $idCompte, string $cle): bool
    {
        $corps = preg_split('/\s+/', $cle)[1] ?? '';
        foreach (DB::table('user_ssh_keys')->where('user_id', $idCompte)->pluck('cle') as $existante) {
            if ((preg_split('/\s+/', trim((string) $existante))[1] ?? null) === $corps) {
                return true;
            }
        }

        return false;
    }
}
