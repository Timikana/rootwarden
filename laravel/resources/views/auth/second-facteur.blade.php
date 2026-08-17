@extends('layouts.socle', ['titre' => __('auth.second_facteur_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('auth.second_facteur_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.second_facteur_instruction') }}</p>

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
            </div>
            <button class="rw-bouton" type="submit">{{ __('auth.second_facteur_valider') }}</button>
        </form>
    </div>
</div>
@endsection
