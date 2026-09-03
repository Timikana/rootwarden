@extends('layouts.socle', ['titre' => __('auth.connexion_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ config('app.name') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.connexion_sous_titre') }}</p>

        {{-- Dire ou l'on en est : la connexion se fait en deux temps, autant
             l'annoncer plutot que de laisser decouvrir le second ecran. --}}
        <div class="rw-etapes">
            <div class="rw-etapes__pas rw-etapes__pas--courant">1. {{ __('auth.etape_identifiants') }}</div>
            <div class="rw-etapes__pas">2. {{ __('auth.etape_second_facteur') }}</div>
        </div>

        @if ($errors->any())
            <p class="rw-erreur">{{ $errors->first() }}</p>
        @endif

        <form method="POST" action="{{ route('connexion.soumettre') }}">
            @csrf
            <div class="rw-champ">
                <label class="rw-etiquette" for="username">{{ __('auth.connexion_identifiant') }}</label>
                <input class="rw-saisie" id="username" name="username" type="text"
                       value="{{ old('username') }}" autocomplete="username" autofocus required>
            </div>
            <div class="rw-champ">
                <label class="rw-etiquette" for="password">{{ __('auth.connexion_mot_de_passe') }}</label>
                <input class="rw-saisie" id="password" name="password" type="password"
                       autocomplete="current-password" required>
                <p class="rw-aide">{{ __('auth.connexion_aide') }}</p>
            </div>

            {{-- Action principale a droite : c'est la que l'oeil arrive apres
                 avoir parcouru le formulaire. --}}
            <div class="rw-actions">
                <button class="rw-bouton" type="submit">{{ __('auth.connexion_valider') }}</button>
            </div>
        </form>
    </div>
</div>
@endsection
