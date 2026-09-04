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

            {{-- « SE SOUVENIR DE MOI », ET TROIS PHRASES QUI DISENT CE QU'IL FAIT.

                 La premiere est celle qui compte : **ce cookie ne connecte
                 jamais tout seul.** Il restitue l'identite et renvoie au second
                 facteur — ou a l'enrolement si le compte n'en a pas encore. Le
                 dire est ce qui distingue cette case d'un contournement, et
                 l'ancien portail, lui, laisse passer les comptes sans second
                 facteur (`auth/verify.php:139`, un `if` sans `else`).

                 La deuxieme declare une limite HERITEE DU SCHEMA :
                 `remember_tokens` porte `PRIMARY KEY (user_id)`
                 (`mysql/init.sql:49-55`), donc un seul jeton par compte. Se
                 souvenir ailleurs evince celui-ci — silencieusement si on ne le
                 dit pas. **Une limite qu'on porte sans la declarer devient un
                 choix qu'on assume sans l'avoir fait.**

                 La troisieme est un desagrement de TRANSITION : ce cookie est
                 chiffre par le cadre, l'ancien portail le lit en clair, donc il
                 ne saura pas le lire et l'effacera. On ne l'exempte pas du
                 chiffrement pour autant — un porteur d'identite n'a rien a faire
                 dans une liste d'exceptions. --}}
            <div class="rw-champ">
                <label class="rw-champ rw-champ--case" data-rw="connexion-memorisation-etiquette">
                    <input type="checkbox" name="memorisation" value="1"
                           data-rw="connexion-memorisation" @checked(old('memorisation'))>
                    <span>{{ __('auth.memorisation_libelle') }}</span>
                </label>
                <p class="rw-aide" data-rw="memorisation-duree">
                    {{ __('auth.memorisation_duree', ['jours' => \App\Services\JetonMemorisation::JOURS]) }}
                </p>
                <p class="rw-aide" data-rw="memorisation-un-appareil">{{ __('auth.memorisation_un_appareil') }}</p>
                <p class="rw-aide" data-rw="memorisation-ancien-portail">{{ __('auth.memorisation_ancien_portail') }}</p>
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
