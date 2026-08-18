@extends('layouts.portail', ['titre' => __('nav.dashboard')])

@section('corps')
    <h1 class="rw-titre">{{ __('nav.dashboard') }}</h1>
    <p class="rw-sous-titre">{{ __('auth.connecte_en_tant_que') }} <strong>{{ session('utilisateur_nom') }}</strong></p>

    <p class="rw-encart">{{ __('auth.socle_avertissement') }}</p>

    {{-- Aucun agregat de parc n'est affiche ici. Le tableau de bord du legacy
         sert la taille du parc, les CVE critiques, la note d'audit SSH et les
         noms de cinq comptes a des roles sans aucune permission. Il sera porte
         AVEC son cloisonnement, pas avant. --}}
@endsection
