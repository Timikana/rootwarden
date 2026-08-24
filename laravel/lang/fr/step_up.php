<?php

/*
 * La re-authentification ponctuelle. Les messages de refus restent volontairement
 * peu bavards : ils disent qu'on refuse, pas ce qui manquerait pour reussir.
 */
return [
    'valide'               => 'Re-authentification validée.',
    'code_invalide'        => 'Code à six chiffres invalide.',
    'code_deja_utilise'    => 'Ce code a déjà été utilisé. Attendez le suivant.',
    'trop_de_tentatives'   => 'Trop de tentatives. Patientez une minute.',
    'action_inconnue'      => 'Cette action n’exige pas de re-authentification.',
    'sans_second_facteur'  => 'Aucun second facteur n’est configuré sur ce compte.',
    'revoque'              => 'Privilèges rendus.',
    'session_absente'      => 'Session expirée. Reconnectez-vous.',
];
