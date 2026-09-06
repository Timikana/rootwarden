@extends('layouts.socle', ['titre' => __('reinit.titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('reinit.titre') }}</h1>
        <p class="rw-sous-titre rw-prose">{{ __('reinit.sous_titre') }}</p>

        {{-- ⚠ LE MEME EMPLACEMENT POUR LES DEUX ISSUES, ET DEUX CLES DE STYLE
             DISTINCTES. Un succes rendu dans un style d'erreur se lit comme un
             echec — et ici le « succes » est justement le message qui ne dit
             RIEN de l'existence du compte. --}}
        @if (session('succes'))
            <p class="rw-annonce rw-annonce--ok rw-prose" data-rw="reinit-annonce">{{ session('succes') }}</p>
        @endif
        @if (session('erreur'))
            <p class="rw-erreur rw-prose" data-rw="reinit-erreur">{{ session('erreur') }}</p>
        @endif

        <form method="POST" action="{{ route('reinit.envoyer') }}">
            @csrf
            <div class="rw-champ">
                <label class="rw-etiquette" for="email">{{ __('reinit.champ_email') }}</label>
                {{-- `type="email"` ET `required` : deux gardes du NAVIGATEUR,
                     qui evitent une soumission vide. Ce ne sont pas des
                     controles — le serveur ne leur delegue rien, et une requete
                     forgee les ignore. --}}
                <input class="rw-saisie" id="email" name="email" type="email"
                       autocomplete="email" autofocus required maxlength="255"
                       data-rw="reinit-email">
            </div>
            <div class="rw-actions">
                <a class="rw-lien rw-actions__gauche" href="{{ route('connexion') }}"
                   data-rw="reinit-retour">{{ __('reinit.retour') }}</a>
                <button class="rw-bouton" type="submit" data-rw="reinit-envoyer">{{ __('reinit.envoyer') }}</button>
            </div>
        </form>
    </div>
</div>
@endsection
