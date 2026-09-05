{{--
    LE COMPTE EN PASTILLE.

    `<details>` et non un menu pilote en JS : il s'ouvre au clavier, se ferme a
    Echap, et fonctionne si le script ne charge pas. Un menu de compte qui
    depend du JS est un menu de compte qui disparait quand le JS tombe — et
    c'est celui qui porte la DECONNEXION.

    Le libelle complet vivait dans l'en-tete et devait etre masque sur petit
    ecran par une regle qui attrapait aussi la pastille de notification et la
    langue. Une pastille n'a pas ce probleme : elle tient a toutes les tailles.
--}}
@php($rwNom = trim((string) session('utilisateur_nom')))
@php($rwInitiales = \Illuminate\Support\Str::upper(collect(preg_split('/\s+/', $rwNom, -1, PREG_SPLIT_NO_EMPTY))->take(2)->map(fn ($m) => mb_substr($m, 0, 1))->implode('')) ?: '?')
<details class="rw-profil" data-rw="profil">
    <summary data-rw="profil-pastille" title="{{ $rwNom }}"
             aria-label="{{ __('auth.connecte_en_tant_que') }} {{ $rwNom }}">{{ $rwInitiales }}</summary>
    <div class="rw-profil__menu">
        <span class="rw-profil__nom" data-rw="profil-nom">{{ $rwNom }}</span>
        <span class="rw-profil__role">{{ __('auth.connecte_en_tant_que') }}</span>
        <a class="rw-bouton rw-bouton--discret" href="{{ route('profil') }}"
           data-rw="profil-lien">{{ __('nav.profil') }}</a>
        <form class="rw-inline" method="POST" action="{{ route('deconnexion') }}">
            @csrf
            <button class="rw-bouton rw-bouton--discret" type="submit"
                    data-rw="profil-deconnexion">{{ __('nav.logout') }}</button>
        </form>
    </div>
</details>
