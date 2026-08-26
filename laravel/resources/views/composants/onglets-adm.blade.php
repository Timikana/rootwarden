{{--
    Sous-navigation des trois pages d'administration — sous-lot D6a.

    `admin_page.php` porte trois onglets JavaScript sous une seule URL ; le
    portage en fait trois PAGES. Ce partiel est leur seul point commun, et il
    vit donc a un seul endroit : trois copies auraient fini par diverger, comme
    le legacy decrit deux fois son propre menu.

    L'ONGLET DES PERMISSIONS N'EST MONTRE QU'AU ROLE 3, parce que sa route
    l'exige (`role:3` + `perm:can_admin_portal`). Un onglet visible menant a un
    403 est pire qu'un onglet absent : il donne a croire a un droit qu'on n'a
    pas. Les deux autres pages exigent `role:2`, deja acquis pour arriver ici.

    Ceci est un choix d'AFFICHAGE. La garde reste l'intergiciel de la route :
    masquer un lien n'a jamais protege quoi que ce soit.

    @param  string  $courant  'comptes' | 'serveurs' | 'permissions'
--}}
@php($roleCourant = (int) session('role_id', 0))
<nav class="rw-onglets" aria-label="{{ __('adm.nav_titre') }}" data-rw="adm-onglets">
    <a class="rw-onglet @if ($courant === 'comptes') rw-onglet--actif @endif"
       @if ($courant === 'comptes') aria-current="page" @endif
       data-rw="adm-onglet-comptes"
       href="{{ route('comptes') }}">{{ __('adm.nav_comptes') }}</a>

    <a class="rw-onglet @if ($courant === 'serveurs') rw-onglet--actif @endif"
       @if ($courant === 'serveurs') aria-current="page" @endif
       data-rw="adm-onglet-serveurs"
       href="{{ route('serveurs') }}">{{ __('adm.nav_serveurs') }}</a>

    @if ($roleCourant >= 3)
        <a class="rw-onglet @if ($courant === 'permissions') rw-onglet--actif @endif"
           @if ($courant === 'permissions') aria-current="page" @endif
           data-rw="adm-onglet-permissions"
           href="{{ route('permissions') }}">{{ __('adm.nav_permissions') }}</a>
    @endif
</nav>
