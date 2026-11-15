{{--
  Une icone du sprite Lucide (public/icones/lucide.svg, regenere par
  scripts/sprite-icones.py). PAS `/icons/` : Apache y sert ses propres icones
  (Alias de mod_alias), et le sprite y rendait 404 sans erreur visible.

  Attend : $nom (sans le prefixe « i- »), et $classe en option.
--}}
<svg class="rw-icone {{ $classe ?? '' }}" aria-hidden="true" focusable="false"><use href="/icones/lucide.svg?v={{ @filemtime(public_path('icones/lucide.svg')) ?: '0' }}#i-{{ $nom }}"></use></svg>
