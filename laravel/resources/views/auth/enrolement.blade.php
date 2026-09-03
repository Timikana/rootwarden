@extends('layouts.socle', ['titre' => __('auth.enrolement_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('auth.enrolement_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.enrolement_explication') }}</p>

        <div class="rw-etapes">
            <div class="rw-etapes__pas rw-etapes__pas--fait">1. {{ __('auth.etape_identifiants') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--courant">2. {{ __('auth.etape_second_facteur') }}</div>
        </div>

        @if ($errors->any())
            <p class="rw-erreur" data-rw="enrolement-message">{{ $errors->first() }}</p>
        @endif

        {{-- LE QR EN SVG, ET NON EN PNG.
             Le conteneur du portage n'a ni gd ni imagick (mesure) : le legacy
             rend un PNG en base64, ce qui est ici impossible. Le SVG s'inscrit
             dans la page, ne demande aucune extension, et reste net a toute
             taille. Il est produit par le SERVEUR, jamais par un script. --}}
        <div class="rw-qr" data-rw="enrolement-qr" role="img"
             aria-label="{{ __('auth.enrolement_qr_alt') }}">
            {!! $qr !!}
        </div>

        {{-- La saisie manuelle, pour qui ne peut pas scanner. --}}
        <p class="rw-aide">{{ __('auth.enrolement_saisie_manuelle') }}</p>
        <p class="rw-secret select-all" data-rw="enrolement-secret">{{ $secret }}</p>

        <form method="POST" action="{{ route('second-facteur.activer') }}">
            @csrf
            <div class="rw-champ">
                <label class="rw-etiquette" for="2fa_code">{{ __('auth.second_facteur_sous_titre') }}</label>
                {{-- Le nom du champ est celui du legacy : le meme test vise les deux cibles. --}}
                <input class="rw-saisie rw-saisie--code" id="2fa_code" name="2fa_code" type="text"
                       inputmode="numeric" autocomplete="one-time-code" maxlength="6"
                       autofocus required data-rw="enrolement-code">
            </div>

            <div class="rw-actions">
                <a class="rw-bouton rw-bouton--discret rw-actions__gauche"
                   href="{{ route('connexion') }}">{{ __('auth.revenir') }}</a>
                <button class="rw-bouton" type="submit"
                        data-rw="enrolement-activer">{{ __('auth.enrolement_activer') }}</button>
            </div>
        </form>
    </div>
</div>
@endsection
