<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Tests\TestCase;

/**
 * DURCISSEMENT DU PORTAIL — audit de sécurité du 2026-10-13.
 *
 * Chaque test garde un constat de l'audit, et a été vu ÉCHOUER sur le code
 * d'avant avant d'être vu passer.
 */
class DurcissementPortailTest extends TestCase
{
    /**
     * M-2 · Le disque `local` servait ses fichiers par URL signée.
     *
     * `'serve' => true` (défaut du squelette Laravel) crée `GET` et
     * `PUT /storage/{path}` SANS AUCUN middleware, gardés par la seule signature
     * calculée avec `APP_KEY` (`vendor/.../Filesystem/ServeFile.php`,
     * `ReceiveFile.php`). Le portail n'utilise ni `Storage::` ni URL signée : ces
     * deux routes ne servaient à rien, sinon à offrir une lecture ET une écriture
     * de fichiers à quiconque obtient l'`APP_KEY` — qui a fuité le 2026-10-01.
     */
    #[Test]
    public function le_disque_local_ne_sert_aucun_fichier(): void
    {
        $this->assertFalse(Route::has('storage.local'), 'GET /storage/{path} existe encore');
        $this->assertFalse(Route::has('storage.local.upload'), 'PUT /storage/{path} existe encore');
        $this->assertFalse((bool) config('filesystems.disks.local.serve'));
    }

    #[Test]
    public function une_requete_sur_storage_ne_trouve_rien(): void
    {
        // Témoin de bout en bout : sans la route, le cadre rend 404 avant toute
        // vérification de signature.
        $this->get('/storage/nimporte-quoi.txt')->assertNotFound();
    }

    /**
     * M-1 · Le cookie de session partait sans `Secure`.
     *
     * `'secure' => env('SESSION_SECURE_COOKIE')`, sans défaut : `null`, mesuré
     * en production le 2026-10-05. Le port 8080 ne fait que rediriger vers
     * HTTPS, mais la PREMIÈRE requête HTTP d'un navigateur emporte le cookie en
     * clair. Le défaut suit désormais le mode TLS : sécurisé, sauf si
     * `SSL_MODE=disabled` — où le portail est servi en clair et où un cookie
     * `Secure` casserait la connexion.
     */
    #[Test]
    public function le_cookie_de_session_est_securise_par_defaut(): void
    {
        $this->assertSame(true, $this->secureAvec([]), 'aucune variable : le cookie doit etre Secure');
        $this->assertSame(true, $this->secureAvec(['SSL_MODE' => 'auto']));
        $this->assertSame(true, $this->secureAvec(['SSL_MODE' => 'custom']));
    }

    #[Test]
    public function sans_tls_le_cookie_ne_peut_pas_etre_securise(): void
    {
        $this->assertSame(false, $this->secureAvec(['SSL_MODE' => 'disabled']));
    }

    #[Test]
    public function la_variable_explicite_l_emporte_toujours(): void
    {
        $this->assertSame(false, $this->secureAvec(['SESSION_SECURE_COOKIE' => 'false']));
        $this->assertSame(true, $this->secureAvec(['SESSION_SECURE_COOKIE' => 'true', 'SSL_MODE' => 'disabled']));
    }

    /** Relit `config/session.php` sous un environnement donné, puis le restaure. */
    private function secureAvec(array $env): mixed
    {
        $noms = ['SESSION_SECURE_COOKIE', 'SSL_MODE'];
        $avant = [];
        foreach ($noms as $n) {
            $avant[$n] = [$_ENV[$n] ?? null, $_SERVER[$n] ?? null, getenv($n)];
            unset($_ENV[$n], $_SERVER[$n]);
            putenv($n);
            if (array_key_exists($n, $env)) {
                $_ENV[$n] = $_SERVER[$n] = $env[$n];
                putenv("{$n}={$env[$n]}");
            }
        }
        try {
            return (require config_path('session.php'))['secure'];
        } finally {
            foreach ($avant as $n => [$e, $s, $g]) {
                unset($_ENV[$n], $_SERVER[$n]);
                putenv($n);
                if ($e !== null) { $_ENV[$n] = $e; }
                if ($s !== null) { $_SERVER[$n] = $s; }
                if ($g !== false) { putenv("{$n}={$g}"); }
            }
        }
    }
}
