@extends('layouts.socle', ['titre' => __('auth.cgu_titre')])

@section('corps')
<div class="rw-centre">
    <div class="rw-carte rw-carte--large">
        <h1 class="rw-titre">{{ __('auth.cgu_titre') }}</h1>
        <p class="rw-sous-titre">{{ __('auth.cgu_sous_titre') }}</p>

        <div class="rw-etapes">
            <div class="rw-etapes__pas rw-etapes__pas--fait">1. {{ __('auth.etape_identifiants') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--fait">2. {{ __('auth.etape_second_facteur') }}</div>
            <div class="rw-etapes__pas rw-etapes__pas--courant">3. {{ __('auth.etape_acces') }}</div>
        </div>

        {{--
            ══ UN ENCART ANNONCAIT L'ETAT DE LA MIGRATION. RETIRE. ══════════

            Il disait « Seul le socle d'authentification est porte. Les pages du
            portail restent sur l'ancienne interface. »

            Ecrit le 2026-08-17 (`d41d043`), **il etait VRAI ce jour-la**. Le
            menu est passe a 32 entrees portees sur 32 le 2026-09-02 : la phrase
            est fausse depuis SEIZE JOURS, sur l'ecran ou l'on invite quelqu'un a
            accepter des conditions.

            ── POURQUOI ELLE N'EST PAS REMPLACEE PAR SA NEGATION ────────────

            Un ecran n'a pas a annoncer qu'il est porte : une interface qui se
            felicite d'exister est un decor. La phrase avait un sens parce
            qu'elle PREVENAIT d'un manque ; il n'y a plus de manque a prevenir,
            donc plus rien a dire.

            Ecrire « toutes les pages sont portees » recreerait la meme dette —
            **une affirmation d'etat pourrit au prochain changement**, et c'est
            precisement le motif que ce chantier a paye quatre fois en une nuit
            (`pare-feu`, `superv` ×3, et ici).

            Cette page porte les CONDITIONS D'UTILISATION. L'avancement d'un
            chantier interne n'y a pas sa place.
        --}}

        {{-- Deux actions, donc DEUX formulaires cote a cote — jamais imbriques :
             un formulaire dans un formulaire est invalide et le plus interne
             ne part jamais. Refuser a gauche, accepter a droite.

             `data-rw` est le CONTRAT DOM des tests. Un test ancre sur « le
             premier bouton de type submit » est fragile par construction :
             deplacer un bouton l'a fait cliquer « Refuser » au lieu
             d'« Accepter », et il se deconnectait en croyant entrer. --}}
    {{-- ⚠ CETTE PAGE N'AFFICHAIT AUCUNE CONDITION. Titre, fil d'etapes et deux
         boutons — et rien entre les deux. On demandait d'accepter ce qu'on ne
         montrait pas, et un consentement a des termes invisibles n'en est pas un.

         Texte porte depuis `legacy/lang/*/terms.php`, 36 cles, SANS reecriture :
         un texte qui engage ne se paraphrase pas.

         La liste des sections est ecrite ICI plutot que derivee du catalogue :
         l'ordre des articles d'une CGU est une decision, pas un effet de bord
         d'un tri de cles. --}}
    <div class="rw-cgu" data-rw="cgu-texte">
        <p class="rw-cgu__date">{{ __('cgu.last_updated') }}</p>

        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s1_title') }}</h2>
            <p>{{ __('cgu.s1_p1', ['nom' => config('app.name')]) }}</p>
            <p>{{ __('cgu.s1_p2') }}</p>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s2_title') }}</h2>
            <ul class="rw-cgu__liste">
                <li>{{ __('cgu.s2_l1') }}</li>
                <li>{{ __('cgu.s2_l2') }}</li>
                <li>{{ __('cgu.s2_l3') }}</li>
                <li>{{ __('cgu.s2_l4') }}</li>
                <li>{{ __('cgu.s2_l5') }}</li>
            </ul>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s3_title') }}</h2>
            <ul class="rw-cgu__liste">
                <li>{{ __('cgu.s3_l1') }}</li>
                <li>{{ __('cgu.s3_l2') }}</li>
                <li>{{ __('cgu.s3_l3') }}</li>
                <li>{{ __('cgu.s3_l4') }}</li>
            </ul>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s4_title') }}</h2>
            <ul class="rw-cgu__liste">
                <li>{{ __('cgu.s4_l1') }}</li>
                <li>{{ __('cgu.s4_l2') }}</li>
                <li>{{ __('cgu.s4_l3') }}</li>
                <li>{{ __('cgu.s4_l4') }}</li>
                <li>{{ __('cgu.s4_l5') }}</li>
            </ul>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s5_title') }}</h2>
            <p>{{ __('cgu.s5_p1') }}</p>
            <p>{{ __('cgu.s5_p2') }}</p>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s6_title') }}</h2>
            <ul class="rw-cgu__liste">
                <li>{{ __('cgu.s6_l1') }}</li>
                <li>{{ __('cgu.s6_l2') }}</li>
                <li>{{ __('cgu.s6_l3') }}</li>
            </ul>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s7_title') }}</h2>
            <p>{{ __('cgu.s7_p1') }}</p>
        </section>
        <section class="rw-cgu__section">
            <h2 class="rw-cgu__titre">{{ __('cgu.s8_title') }}</h2>
            <p>{{ __('cgu.s8_p1') }}</p>
            {{-- ⚠ LA PHRASE FINISSAIT SUR UN DEUX-POINTS SUIVI DE RIEN. La section
                 s'appelle « Contact » et ne nommait personne. Le legacy rendait
                 l'adresse juste apres (`_deprecated/terms.php:109`), depuis
                 `SERVER_ADMIN` ; le portage l'a perdue au passage. --}}
            <p class="rw-cgu__contact" data-rw="cgu-contact">
                <a href="mailto:{{ config('app.contact_admin') }}">{{ config('app.contact_admin') }}</a>
            </p>
        </section>

        {{-- ⚠ CE BLOC N'ETAIT RENDU NULLE PART. `support_title` et `support_desc`
             vivent dans le catalogue depuis le portage du 05/09 et n'avaient
             AUCUN lecteur : deux cles mortes sur 36. Le legacy les rendait ici
             meme, avec le lien de soutien (`_deprecated/terms.php:114-124`). --}}
        <section class="rw-cgu__soutien" data-rw="cgu-soutien">
            <span class="rw-cgu__soutien-icone" aria-hidden="true">&#9749;</span>
            <div>
                <p class="rw-cgu__soutien-titre">{{ __('cgu.support_title') }}</p>
                <p class="rw-cgu__soutien-texte">{{ __('cgu.support_desc', ['nom' => config('app.name')]) }}</p>
                <a class="rw-cgu__cafe" href="https://buymeacoffee.com/timikana"
                   target="_blank" rel="noopener" data-rw="cgu-cafe">Buy me a coffee</a>
            </div>
        </section>
    </div>

        <div class="rw-actions">
            <form class="rw-inline rw-actions__gauche" method="POST" action="{{ route('deconnexion') }}">
                @csrf
                <button class="rw-bouton rw-bouton--discret" type="submit"
                        data-rw="cgu-refuser">{{ __('auth.cgu_refuser') }}</button>
            </form>
            <form class="rw-inline" method="POST" action="{{ route('cgu.accepter') }}">
                @csrf
                <button class="rw-bouton" type="submit"
                        data-rw="cgu-accepter">{{ __('auth.cgu_accepter') }}</button>
            </form>
        </div>
    </div>
</div>
@endsection
