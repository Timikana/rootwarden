@extends('layouts.socle', ['titre' => __('auth.enrolement_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('auth.enrolement_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.enrolement_explication') }}</p>

        {{-- Aucun acces n'est accorde ici : un compte sans second facteur ne
             franchit pas cet ecran. Mieux vaut une impasse explicite qu'une
             porte ouverte. --}}
        <p class="rw-note">
            <a class="rw-lien" href="{{ config('app.url_legacy', 'https://localhost:8443') }}/auth/enable_2fa.php"
               target="_blank" rel="noopener">{{ __('auth.ouvrir_ancien_portail') }} ↗</a>
        </p>
    </div>
</div>
@endsection
