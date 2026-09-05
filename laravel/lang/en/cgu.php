<?php

/*
 * LES CONDITIONS D'UTILISATION, PORTEES DEPUIS LE LEGACY LE 2026-09-05.
 *
 * ⚠ La page `/cgu` du portage affichait son TITRE, son fil d'etapes et ses
 * deux boutons — et AUCUN texte de conditions. On demandait d'accepter ce
 * qu'on ne montrait pas. Un consentement a des termes invisibles n'est pas
 * un consentement, et une page d'engagement n'existe que pour etre
 * opposable.
 *
 * Source : `legacy/lang/en/terms.php`, 36 cles, portees sans
 * reecriture — le texte engage, il ne se paraphrase pas.
 */

return [
    'page_title' => 'Terms of Service',
    'accept' => 'I accept the terms',
    'last_updated' => 'Last updated:',
    's1_title' => '1. Purpose',
    's1_p1' => 'These Terms of Service govern the access and use of the RootWarden platform, an internal tool for centralized Linux infrastructure management (SSH keys, updates, firewall, services, vulnerabilities).',
    's1_p2' => 'By accessing the platform, you agree to be bound by these terms. If you do not agree, please do not use the platform.',
    's2_title' => '2. Access and authentication',
    's2_l1' => 'Access is restricted to users with an account assigned by an administrator.',
    's2_l2' => 'Two-factor authentication (TOTP) is mandatory. No workaround is permitted.',
    's2_l3' => 'Credentials (password, TOTP secret) are strictly personal and must never be shared.',
    's2_l4' => 'Passwords must comply with the security policy: minimum 15 characters, 1 uppercase, 1 lowercase, 1 digit, 1 special character.',
    's2_l5' => 'Every login is logged (IP address, user-agent, timestamp).',
    's3_title' => '3. User responsibilities',
    's3_l1' => 'You are responsible for all actions performed through your account, including SSH key deployments, system updates, and firewall changes.',
    's3_l2' => 'You agree to use the platform only within the scope of your professional duties and the permissions assigned to you.',
    's3_l3' => 'Any anomaly or suspected compromise must be reported immediately to the administration team.',
    's3_l4' => 'You must not attempt to access servers, data, or features for which you have not received explicit authorization.',
    's4_title' => '4. Prohibited activities',
    's4_l1' => 'Attempting to bypass authentication mechanisms or escalate privileges.',
    's4_l2' => 'Using the platform for malicious, destructive, or unauthorized actions on managed servers.',
    's4_l3' => 'Modifying, deleting, or exfiltrating data without authorization (SSH keys, configurations, credentials).',
    's4_l4' => 'Sharing your credentials or access with third parties, including colleagues.',
    's4_l5' => 'Disabling or circumventing logging and audit mechanisms.',
    's5_title' => '5. Traceability and audit',
    's5_p1' => 'All actions performed on the platform are recorded in an audit log: logins, permission changes, deployments, security scans, etc.',
    's5_p2' => 'These logs are retained for security, compliance, and incident resolution purposes. They may be reviewed by authorized administrators.',
    's6_title' => '6. Limitation of liability',
    's6_l1' => 'The platform is provided "as is". The administration team strives to ensure its availability but does not guarantee uninterrupted operation.',
    's6_l2' => 'The administration team shall not be held liable for damages resulting from misuse of the platform or non-compliance with these terms.',
    's6_l3' => 'Operations performed on remote servers (updates, iptables changes, service restarts) are the responsibility of the user who initiates them.',
    's7_title' => '7. Changes',
    's7_p1' => 'These terms may be updated at any time. Users will be notified of significant changes. Continued use of the platform constitutes acceptance of the new terms.',
    's8_title' => '8. Contact',
    's8_p1' => 'For any questions regarding these terms or to report a security incident, contact the administration team:',
    'support_title' => 'Support the project',
    'support_desc' => 'RootWarden is an independent open-source project. If you use it and it saves you time, you can support its development.',
];
