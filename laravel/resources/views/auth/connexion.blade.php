@extends('layouts.socle', ['titre' => __('auth.connexion_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ config('app.name') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.connexion_titre') }}</p>

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
            </div>
            <button class="rw-bouton" type="submit">{{ __('auth.connexion_valider') }}</button>
        </form>
    </div>
</div>
@endsection
