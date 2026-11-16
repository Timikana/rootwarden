{{--
  Une icone du sprite Lucide (public/icones/lucide.svg, regenere par
  scripts/sprite-icones.py). PAS `/icons/` : Apache y sert ses propres icones
  (Alias de mod_alias), et le sprite y rendait 404 sans erreur visible.

  Usage : <x-icone nom="bell" />, ou <x-icone nom="shield" classe="rw-marque__icone" />.
  `nom` sans le prefixe « i- ».

  UN COMPOSANT, PAS UN @include : un @include voit toutes les variables de la
  vue qui l'appelle, et `@extends` les transmet a la mise en page. La page de la
  cle de plateforme definit `$classe` dans une boucle de boutons ; le `$classe ?? ''`
  de l'ancien include la recuperait, et TOUTES les icones du menu recevaient
  `rw-bouton rw-bouton--danger` : des pastilles rouges vides a la place des
  icones. Un composant ne voit que ses attributs : la fuite ne s'ecrit plus.
--}}
@props(['nom', 'classe' => ''])
<svg class="rw-icone {{ $classe }}" aria-hidden="true" focusable="false"><use href="/icones/lucide.svg?v={{ @filemtime(public_path('icones/lucide.svg')) ?: '0' }}#i-{{ $nom }}"></use></svg>
