@extends('layouts.socle', ['titre' => __('reinit.reinit_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte">
        <h1 class="rw-titre">{{ __('reinit.reinit_titre') }}</h1>

        @if (session('erreur'))
            <p class="rw-erreur rw-prose" data-rw="reinit-erreur">{{ session('erreur') }}</p>
        @endif

        @if (! $valide)
            {{-- LE FORMULAIRE N'EST PAS RENDU SI LE JETON NE VAUT RIEN. Afficher
                 une saisie qui sera refusee ferait choisir un mot de passe, le
                 confirmer, et decouvrir seulement ensuite que le lien etait mort.
                 Le geste offert est celui qui MARCHE : redemander un lien. --}}
            <p class="rw-erreur rw-prose" data-rw="reinit-jeton-invalide">{{ __('reinit.jeton_invalide') }}</p>
            <div class="rw-actions">
                <a class="rw-bouton" href="{{ route('reinit.demander') }}"
                   data-rw="reinit-redemander">{{ __('reinit.envoyer') }}</a>
            </div>
        @else
            <p class="rw-sous-titre rw-prose">{{ __('reinit.reinit_sous_titre') }}</p>

            {{-- LA CONSEQUENCE EST DITE AVANT LE GESTE. Quelqu'un qui
                 reinitialise parce qu'il soupconne un acces doit savoir que ce
                 geste ferme les sessions ouvertes — c'est justement ce qu'il
                 cherche, et le taire le laisserait douter. --}}
            <p class="rw-aide rw-prose" data-rw="reinit-consequence">{{ __('reinit.consequence') }}</p>

            <form method="POST" action="{{ route('reinit.appliquer') }}">
                @csrf
                {{-- Le jeton voyage en champ cache : il a deja circule dans
                     l'URL du courriel, et le remettre dans l'URL de la
                     soumission le deposerait dans le journal du serveur. --}}
                <input type="hidden" name="uid" value="{{ $uid }}">
                <input type="hidden" name="jeton" value="{{ $jeton }}">

                <div class="rw-champ">
                    <label class="rw-etiquette" for="mot_de_passe">{{ __('reinit.champ_mot_de_passe') }}</label>
                    <input class="rw-saisie" id="mot_de_passe" name="mot_de_passe" type="password"
                           autocomplete="new-password" autofocus required
                           minlength="{{ \App\Services\Comptes::LONGUEUR_MINIMALE }}"
                           data-rw="reinit-mot-de-passe">
                    {{-- ⚠ LES DEUX JETONS DE CETTE CLE, PAS UN SEUL.
                         `mdp_politique` porte `:longueur` ET `:historique` ; mon
                         premier jet n'en liait aucun des deux correctement, et un
                         jeton non lie s'affiche EN CLAIR a l'ecran — sans erreur,
                         sans qu'aucun controle i18n le voie. Les valeurs viennent
                         des memes constantes que celles de `profil`, pas d'un
                         second jeu de nombres. --}}
                    <p class="rw-aide">{{ __('profil.mdp_politique', [
                        'longueur' => \App\Services\Comptes::LONGUEUR_MINIMALE,
                        'historique' => (int) config('rootwarden.mot_de_passe.taille_historique', 5),
                    ]) }}</p>
                </div>
                <div class="rw-champ">
                    <label class="rw-etiquette" for="confirmation">{{ __('reinit.champ_confirmation') }}</label>
                    <input class="rw-saisie" id="confirmation" name="confirmation" type="password"
                           autocomplete="new-password" required
                           minlength="{{ \App\Services\Comptes::LONGUEUR_MINIMALE }}"
                           data-rw="reinit-confirmation">
                </div>
                <div class="rw-actions">
                    <a class="rw-lien rw-actions__gauche" href="{{ route('connexion') }}">{{ __('reinit.retour') }}</a>
                    <button class="rw-bouton" type="submit" data-rw="reinit-valider">{{ __('reinit.valider') }}</button>
                </div>
            </form>
        @endif
    </div>
</div>
@endsection
