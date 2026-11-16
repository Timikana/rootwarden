<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\Blade;
use Tests\TestCase;

/**
 * UNE VARIABLE DE LA PAGE N'ATTEINT PAS L'ICONE.
 *
 * L'icone etait un `@include` qui lisait `$classe ?? ''`. Un `@include` voit
 * toutes les variables de la vue appelante, et `@extends` les transmet a la
 * mise en page. La page de la cle de plateforme definit `$classe` dans sa boucle
 * de boutons (la derniere valeur : `rw-bouton rw-bouton--danger`) : toutes les
 * icones du menu et de la barre du haut la recevaient, et se peignaient en
 * pastilles rouges vides. Mesure du 2026-11-16 sur la pile isolee : la cloche
 * faisait 34x18 sur cette page, 16x16 sur les 33 autres.
 *
 * Le composant `<x-icone>` ne voit que ses attributs. Ce test le verifie, avec
 * un temoin : une classe PASSEE en attribut, elle, doit arriver.
 */
class IconeIsoleeTest extends TestCase
{
    public function test_une_variable_classe_de_la_page_n_atteint_pas_l_icone(): void
    {
        $html = Blade::render('@php($classe = "rw-bouton rw-bouton--danger")<x-icone nom="bell" />');

        $this->assertStringContainsString('#i-bell', $html);
        $this->assertStringNotContainsString('rw-bouton', $html);
    }

    public function test_temoin_une_classe_passee_en_attribut_arrive(): void
    {
        $html = Blade::render('<x-icone nom="shield" classe="rw-marque__icone" />');

        $this->assertStringContainsString('rw-icone rw-marque__icone', $html);
    }

    public function test_l_ancien_include_n_existe_plus(): void
    {
        // Le revenir par un `@include('composants.icone')` copie d'une ancienne
        // vue rouvrirait la fuite : le fichier n'existe plus, l'appel echoue.
        $this->assertFileDoesNotExist(resource_path('views/composants/icone.blade.php'));
    }
}
