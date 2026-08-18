@extends('layouts.socle', ['titre' => __('auth.second_facteur_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('auth.second_facteur_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.second_facteur_instruction') }}</p>

        <div class="rw-etapes">
            <div class="rw-etapes__pas rw-etapes__pas--fait">1. {{ __('auth.etape_identifiants') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--courant">2. {{ __('auth.etape_second_facteur') }}</div>
        </div>

        @if ($errors->any())
            <p class="rw-erreur">{{ $errors->first() }}</p>
        @endif

        <form method="POST" action="{{ route('second-facteur.soumettre') }}">
            @csrf
            <div class="rw-champ">
                <label class="rw-etiquette" for="2fa_code">{{ __('auth.second_facteur_sous_titre') }}</label>
                {{-- Le nom du champ est celui du legacy : le meme test vise les deux cibles. --}}
                <input class="rw-saisie rw-saisie--code" id="2fa_code" name="2fa_code" type="text"
                       inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus required>
                <p class="rw-aide">{{ __('auth.second_facteur_aide') }}</p>
            </div>

            {{-- Retour a gauche, action principale a droite : l'utilisateur qui
                 s'est trompe d'identifiant doit pouvoir revenir sans chercher. --}}
            <div class="rw-actions">
                <a class="rw-bouton rw-bouton--discret rw-actions__gauche"
                   href="{{ route('connexion') }}">{{ __('auth.revenir') }}</a>
                <button class="rw-bouton" type="submit">{{ __('auth.second_facteur_valider') }}</button>
            </div>
        </form>
    </div>
</div>
@endsection
