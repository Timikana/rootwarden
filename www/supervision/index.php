<?php
/**
 * supervision/index.php - Module Supervision : deploiement et configuration agents.
 *
 * 4 onglets :
 *   1. Configuration globale - template agent (Server, TLS, PSK, metadata)
 *   2. Deploiement agents   - tableau serveurs, deploy/reconfigure/uninstall
 *   3. Editeur de config    - charge/modifie/sauvegarde le fichier agent distant
 *   4. Monitoring           - placeholder pour integration API Zabbix (Phase 3)
 *
 * Permissions : admin (2) + superadmin (3) + can_manage_supervision
 */
require_once __DIR__ . '/../auth/verify.php';
require_once __DIR__ . '/../includes/lang.php';
require_once __DIR__ . '/../db.php';

checkAuth([ROLE_ADMIN, ROLE_SUPERADMIN]);
checkPermission('can_manage_supervision');

// Chargement des serveurs (non archives)
$stmt = $pdo->query("
    SELECT m.id, m.name, m.ip, m.port, m.environment, m.network_type,
           m.zabbix_agent_version, m.online_status, m.linux_version
    FROM machines m
    WHERE m.lifecycle_status IS NULL OR m.lifecycle_status != 'archived'
    ORDER BY m.name
");
$machines = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Config globale existante (zabbix par defaut)
$cfgStmt = $pdo->query("SELECT * FROM supervision_config WHERE platform = 'zabbix' ORDER BY id DESC LIMIT 1");
$globalConfig = $cfgStmt->fetch(PDO::FETCH_ASSOC) ?: null;

// Agents installes par machine (tous les agents)
$agentsMap = [];
try {
    $agStmt = $pdo->query("SELECT machine_id, platform, agent_version, config_deployed FROM supervision_agents");
    while ($ag = $agStmt->fetch(PDO::FETCH_ASSOC)) {
        $agentsMap[(int)$ag['machine_id']][$ag['platform']] = $ag;
    }
} catch (Exception $e) {
    // Table pas encore creee (migration pas passee)
}
?>
<!DOCTYPE html>
<html lang="<?= getLang() ?>">
<head>
    <?php require_once __DIR__ . '/../head.php'; ?>
    <title><?= t('supervision.title') ?></title>
    <style>
        .tab-btn { transition: all 0.15s; }
        .tab-btn.active { border-bottom: 2px solid #3b82f6; color: #3b82f6; font-weight: 600; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }
        .logs-container { display: flex; flex-wrap: wrap; gap: 1rem; }
        .server-log-window {
            border: 1px solid #444; background-color: #1e1e1e; color: #d4d4d4;
            width: 45%; min-height: 200px; max-height: 400px;
            padding: 0.5rem; overflow-y: auto; border-radius: 5px;
        }
        .server-log-window h3 { margin: 0 0 0.5rem 0; font-size: 1.1rem; color: #90caf9; }
        .log-line { margin: 0; padding: 2px 0; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body class="bg-gray-100 dark:bg-gray-900 text-gray-800 dark:text-gray-200">

    <?php require_once __DIR__ . '/../menu.php'; ?>

    <div class="px-6 py-6 max-w-screen-xl mx-auto">

        <!-- Header + selecteur agent -->
        <div class="flex items-start justify-between mb-6">
            <div>
                <h1 class="text-2xl font-bold text-gray-800 dark:text-gray-100"><?= t('supervision.title') ?></h1>
                <p class="text-sm text-gray-500 dark:text-gray-400"><?= t('supervision.subtitle') ?></p>
<?php $tipId = 'supervision'; $tipTitle = t('tip.supervision_title'); $tipSteps = [t('tip.supervision_step1'), t('tip.supervision_step2'), t('tip.supervision_step3'), t('tip.supervision_step4')]; require __DIR__ . '/../includes/howto_tip.php'; ?>
            </div>
            <div class="flex items-center gap-3">
                <label class="text-xs font-medium text-gray-500 dark:text-gray-400"><?= t('supervision.agent_platform') ?></label>
                <select id="agent-platform" onchange="switchAgentPlatform(this.value)" class="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:ring-2 focus:ring-blue-500">
                    <option value="zabbix" selected>Zabbix</option>
                    <option value="centreon">Centreon</option>
                    <option value="prometheus">Prometheus Node Exporter</option>
                    <option value="telegraf">Telegraf</option>
                </select>
            </div>
        </div>

        <!-- Onglets -->
        <div class="border-b border-gray-200 dark:border-gray-700 mb-6">
            <nav class="flex gap-6">
                <button class="tab-btn active px-1 py-3 text-sm" data-tab="config"><?= t('supervision.tab_config') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500 dark:text-gray-400" data-tab="profiles"><?= t('supervision.tab_profiles') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500 dark:text-gray-400" data-tab="deploy"><?= t('supervision.tab_deploy') ?></button>
                <button class="tab-btn px-1 py-3 text-sm text-gray-500 dark:text-gray-400" data-tab="editor"><?= t('supervision.tab_editor') ?></button>
            </nav>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════════
             ONGLET 1 : Configuration globale
             ═══════════════════════════════════════════════════════════════════ -->
        <div id="tab-config" class="tab-panel active">
            <div id="config-zabbix" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
                <h2 class="text-lg font-bold mb-1"><?= t('supervision.config_title') ?></h2>
                <p class="text-xs text-gray-400 mb-4"><?= t('supervision.config_desc') ?></p>

                <?php if (!$globalConfig): ?>
                <div class="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg text-sm text-yellow-700 dark:text-yellow-300">
                    <?= t('supervision.no_config') ?>
                </div>
                <?php endif; ?>

                <form id="config-form" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <!-- Agent type -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.agent_type') ?></label>
                            <select id="cfg-agent-type" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                <option value="zabbix-agent" <?= ($globalConfig['agent_type'] ?? '') === 'zabbix-agent' ? 'selected' : '' ?>><?= t('supervision.agent_type_legacy') ?></option>
                                <option value="zabbix-agent2" <?= ($globalConfig['agent_type'] ?? 'zabbix-agent2') === 'zabbix-agent2' ? 'selected' : '' ?>><?= t('supervision.agent_type_2') ?></option>
                            </select>
                        </div>
                        <!-- Version -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.agent_version') ?></label>
                            <select id="cfg-agent-version" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                <option value="7.0" <?= ($globalConfig['agent_version'] ?? '7.0') === '7.0' ? 'selected' : '' ?>>7.0 LTS</option>
                                <option value="7.2" <?= ($globalConfig['agent_version'] ?? '') === '7.2' ? 'selected' : '' ?>>7.2</option>
                            </select>
                        </div>
                        <!-- Zabbix Server -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.zabbix_server') ?> *</label>
                            <input type="text" id="cfg-zabbix-server" value="<?= htmlspecialchars($globalConfig['zabbix_server'] ?? '') ?>"
                                   placeholder="zabbix.example.com" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        </div>
                        <!-- ServerActive -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.zabbix_server_active') ?></label>
                            <input type="text" id="cfg-server-active" value="<?= htmlspecialchars($globalConfig['zabbix_server_active'] ?? '') ?>"
                                   placeholder="" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.zabbix_server_active_hint') ?></p>
                        </div>
                        <!-- ListenPort -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.listen_port') ?></label>
                            <input type="number" id="cfg-listen-port" value="<?= htmlspecialchars($globalConfig['listen_port'] ?? '10050') ?>"
                                   class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        </div>
                        <!-- Hostname pattern -->
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.hostname_pattern') ?></label>
                            <input type="text" id="cfg-hostname-pattern" value="<?= htmlspecialchars($globalConfig['hostname_pattern'] ?? '{machine.name}') ?>"
                                   class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.hostname_pattern_hint') ?></p>
                        </div>
                    </div>

                    <!-- TLS -->
                    <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                        <h3 class="text-sm font-semibold mb-3 text-gray-600 dark:text-gray-300">TLS / PSK</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium mb-1"><?= t('supervision.tls_connect') ?></label>
                                <select id="cfg-tls-connect" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                    <option value="unencrypted" <?= ($globalConfig['tls_connect'] ?? 'unencrypted') === 'unencrypted' ? 'selected' : '' ?>><?= t('supervision.tls_unencrypted') ?></option>
                                    <option value="psk" <?= ($globalConfig['tls_connect'] ?? '') === 'psk' ? 'selected' : '' ?>><?= t('supervision.tls_psk') ?></option>
                                    <option value="cert" <?= ($globalConfig['tls_connect'] ?? '') === 'cert' ? 'selected' : '' ?>><?= t('supervision.tls_cert') ?></option>
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1"><?= t('supervision.tls_accept') ?></label>
                                <select id="cfg-tls-accept" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                    <option value="unencrypted" <?= ($globalConfig['tls_accept'] ?? 'unencrypted') === 'unencrypted' ? 'selected' : '' ?>><?= t('supervision.tls_unencrypted') ?></option>
                                    <option value="psk" <?= ($globalConfig['tls_accept'] ?? '') === 'psk' ? 'selected' : '' ?>><?= t('supervision.tls_psk') ?></option>
                                    <option value="cert" <?= ($globalConfig['tls_accept'] ?? '') === 'cert' ? 'selected' : '' ?>><?= t('supervision.tls_cert') ?></option>
                                </select>
                            </div>
                            <div id="psk-fields" class="<?= (($globalConfig['tls_connect'] ?? '') === 'psk' || ($globalConfig['tls_accept'] ?? '') === 'psk') ? '' : 'hidden' ?> col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm font-medium mb-1"><?= t('supervision.tls_psk_identity') ?></label>
                                    <input type="text" id="cfg-psk-identity" value="<?= htmlspecialchars($globalConfig['tls_psk_identity'] ?? '') ?>"
                                           class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium mb-1"><?= t('supervision.tls_psk_value') ?></label>
                                    <input type="password" id="cfg-psk-value" value="<?= $globalConfig && $globalConfig['tls_psk_value'] ? '********' : '' ?>"
                                           class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                    <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.tls_psk_hint') ?></p>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Metadata + Extra -->
                    <div class="border-t border-gray-200 dark:border-gray-700 pt-4">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium mb-1"><?= t('supervision.host_metadata') ?></label>
                                <input type="text" id="cfg-host-metadata" value="<?= htmlspecialchars($globalConfig['host_metadata_template'] ?? '') ?>"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.host_metadata_hint') ?></p>
                            </div>
                        </div>
                        <div class="mt-4">
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.extra_config') ?></label>
                            <textarea id="cfg-extra-config" rows="3"
                                      class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono"
                                      placeholder="# UserParameter=custom.key,command"><?= htmlspecialchars($globalConfig['extra_config'] ?? '') ?></textarea>
                            <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.extra_config_hint') ?></p>
                        </div>
                    </div>

                    <div class="flex justify-end pt-2">
                        <button type="button" onclick="saveGlobalConfig()" class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
                            <?= t('supervision.btn_save_config') ?>
                        </button>
                    </div>
                </form>
            </div>

            <!-- ── Formulaire Centreon (cache par defaut) ────────────────────── -->
            <div id="config-centreon" style="display:none" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
                <h2 class="text-lg font-bold mb-1">Centreon Monitoring Agent</h2>
                <p class="text-xs text-gray-400 mb-4"><?= t('supervision.config_desc') ?></p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.centreon_host') ?> *</label>
                        <input type="text" id="cfg-centreon-host" placeholder="centreon.example.com"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.centreon_port') ?></label>
                        <input type="number" id="cfg-centreon-port" value="4317"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.hostname_pattern') ?></label>
                        <input type="text" id="cfg-centreon-hostname" value="{machine.name}"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.centreon_log_level') ?></label>
                        <select id="cfg-centreon-loglevel" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            <option value="info">info</option>
                            <option value="debug">debug</option>
                            <option value="error">error</option>
                        </select>
                    </div>
                </div>
                <div class="mt-4">
                    <label class="block text-sm font-medium mb-1"><?= t('supervision.extra_config') ?></label>
                    <textarea id="cfg-centreon-extra" rows="3" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono" placeholder="# YAML supplementaire"></textarea>
                </div>
                <div class="flex justify-end pt-4">
                    <button type="button" onclick="savePlatformConfig('centreon')" class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"><?= t('supervision.btn_save_config') ?></button>
                </div>
            </div>

            <!-- ── Formulaire Prometheus (cache par defaut) ──────────────────── -->
            <div id="config-prometheus" style="display:none" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
                <h2 class="text-lg font-bold mb-1">Prometheus Node Exporter</h2>
                <p class="text-xs text-gray-400 mb-4"><?= t('supervision.prometheus_info') ?></p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.prometheus_listen') ?></label>
                        <input type="text" id="cfg-prometheus-listen" value=":9100" placeholder=":9100"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.prometheus_listen_hint') ?></p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.hostname_pattern') ?></label>
                        <input type="text" id="cfg-prometheus-hostname" value="{machine.name}"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.prometheus_collectors') ?></label>
                        <input type="text" id="cfg-prometheus-collectors" placeholder="systemd,textfile,filesystem"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.prometheus_collectors_hint') ?></p>
                    </div>
                </div>
                <div class="mt-4">
                    <label class="block text-sm font-medium mb-1"><?= t('supervision.extra_config') ?></label>
                    <textarea id="cfg-prometheus-extra" rows="3" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono" placeholder="# Flags supplementaires"></textarea>
                </div>
                <div class="flex justify-end pt-4">
                    <button type="button" onclick="savePlatformConfig('prometheus')" class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"><?= t('supervision.btn_save_config') ?></button>
                </div>
            </div>

            <!-- ── Formulaire Telegraf (cache par defaut) ────────────────────── -->
            <div id="config-telegraf" style="display:none" class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
                <h2 class="text-lg font-bold mb-1">Telegraf</h2>
                <p class="text-xs text-gray-400 mb-4"><?= t('supervision.config_desc') ?></p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_output_url') ?></label>
                        <input type="text" id="cfg-telegraf-url" placeholder="http://influxdb:8086"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.telegraf_no_influx') ?></p>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_output_token') ?></label>
                        <input type="password" id="cfg-telegraf-token"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_output_org') ?></label>
                        <input type="text" id="cfg-telegraf-org" placeholder="my-org"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_output_bucket') ?></label>
                        <input type="text" id="cfg-telegraf-bucket" placeholder="my-bucket"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.hostname_pattern') ?></label>
                        <input type="text" id="cfg-telegraf-hostname" value="{machine.name}"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_interval') ?></label>
                        <input type="text" id="cfg-telegraf-interval" value="10s" placeholder="10s"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                    </div>
                    <div class="md:col-span-2">
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.telegraf_inputs') ?></label>
                        <input type="text" id="cfg-telegraf-inputs" value="cpu,mem,disk,diskio,net,system" placeholder="cpu,mem,disk,diskio,net,system"
                               class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.telegraf_inputs_hint') ?></p>
                    </div>
                </div>
                <div class="mt-4">
                    <label class="block text-sm font-medium mb-1"><?= t('supervision.extra_config') ?></label>
                    <textarea id="cfg-telegraf-extra" rows="3" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 font-mono" placeholder="# TOML supplementaire"></textarea>
                </div>
                <div class="flex justify-end pt-4">
                    <button type="button" onclick="savePlatformConfig('telegraf')" class="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"><?= t('supervision.btn_save_config') ?></button>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════════
             ONGLET 2 : Profils de supervision (catalogue metadata)
             ═══════════════════════════════════════════════════════════════════ -->
        <div id="tab-profiles" class="tab-panel">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6">
                <div class="flex items-start justify-between mb-4">
                    <div>
                        <h2 class="text-lg font-bold"><?= t('supervision.profiles_title') ?></h2>
                        <p class="text-xs text-gray-400 mt-1"><?= t('supervision.profiles_desc') ?></p>
                    </div>
                    <button type="button" onclick="openProfileDialog()"
                            class="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">
                        + <?= t('supervision.profile_new') ?>
                    </button>
                </div>
                <div id="profiles-empty" class="hidden py-8 text-center text-sm text-gray-400">
                    <?= t('supervision.profiles_empty') ?>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead class="text-xs uppercase text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                            <tr>
                                <th class="text-left py-2"><?= t('supervision.profile_name') ?></th>
                                <th class="text-left py-2"><?= t('supervision.profile_host_metadata') ?></th>
                                <th class="text-left py-2"><?= t('supervision.profile_server') ?></th>
                                <th class="text-left py-2"><?= t('supervision.profile_proxy') ?></th>
                                <th class="text-center py-2"><?= t('supervision.profile_machines') ?></th>
                                <th class="text-right py-2"></th>
                            </tr>
                        </thead>
                        <tbody id="profiles-tbody"></tbody>
                    </table>
                </div>
                <p class="text-xs text-gray-500 mt-3">
                    <?= t('supervision.profiles_interp_hint') ?>
                </p>
            </div>

            <!-- Dialog CRUD profil -->
            <div id="profile-dialog" class="hidden fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
                    <div class="flex items-center justify-between p-5 border-b border-gray-200 dark:border-gray-700">
                        <h3 class="text-lg font-bold" id="profile-dialog-title"><?= t('supervision.profile_new') ?></h3>
                        <button onclick="closeProfileDialog()" class="text-gray-400 hover:text-gray-600">&times;</button>
                    </div>
                    <div class="p-5 space-y-4">
                        <input type="hidden" id="profile-id" value="">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium mb-1"><?= t('supervision.profile_name') ?> *</label>
                                <input type="text" id="profile-name" placeholder="LinuxInterne"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.profile_name_hint') ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1"><?= t('supervision.profile_host_metadata') ?></label>
                                <input type="text" id="profile-host-metadata" placeholder="LinuxInterne"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                                <p class="text-xs text-gray-400 mt-0.5"><?= t('supervision.profile_host_metadata_hint') ?></p>
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.profile_description') ?></label>
                            <input type="text" id="profile-description"
                                   class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium mb-1">Server (override)</label>
                                <input type="text" id="profile-server" placeholder="(vide = config globale)"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1">ServerActive (override)</label>
                                <input type="text" id="profile-server-active" placeholder="(vide = config globale)"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1">Zabbix Proxy (informatif)</label>
                                <input type="text" id="profile-proxy" placeholder="proxy.example.com"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            </div>
                            <div>
                                <label class="block text-sm font-medium mb-1">ListenPort</label>
                                <input type="number" id="profile-listen-port" placeholder="10050"
                                       class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium mb-1"><?= t('supervision.profile_notes') ?></label>
                            <textarea id="profile-notes" rows="3"
                                      class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"></textarea>
                        </div>
                    </div>
                    <div class="flex justify-end gap-2 p-5 border-t border-gray-200 dark:border-gray-700">
                        <button onclick="closeProfileDialog()"
                                class="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">
                            <?= t('common.cancel') ?>
                        </button>
                        <button onclick="saveProfile()"
                                class="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg">
                            <?= t('common.save') ?>
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════════
             ONGLET 3 : Deploiement agents
             ═══════════════════════════════════════════════════════════════════ -->
        <div id="tab-deploy" class="tab-panel">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4 mb-4">
                <!-- Titre + compteur dynamiques -->
                <div class="flex items-center gap-3 mb-3">
                    <h2 id="deploy-title" class="text-sm font-bold text-gray-700 dark:text-gray-200"><?= t('supervision.deploy_title_platform') ?></h2>
                    <span id="platform-badge" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">ZABBIX</span>
                    <span id="agent-counter" class="text-xs text-gray-400"></span>
                </div>

                <!-- Barre d'actions -->
                <div class="flex flex-wrap items-center gap-2 mb-3">
                    <button type="button" onclick="selectAllDeploy(true)" class="text-xs px-3 py-1.5 rounded-lg border border-green-300 dark:border-green-700 text-green-700 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/30 transition-colors"><?= t('supervision.btn_check_all') ?></button>
                    <button type="button" onclick="selectAllDeploy(false)" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"><?= t('supervision.btn_uncheck_all') ?></button>
                    <span id="deploy-selection-count" class="text-xs text-gray-400 min-w-[60px]"></span>
                    <span class="w-px h-6 bg-gray-300 dark:bg-gray-600 self-center"></span>
                    <button id="btn-deploy" onclick="deploySelected()" class="deploy-action-btn text-xs px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-700 text-white transition-colors font-medium"><?= t('supervision.btn_deploy_selected') ?></button>
                    <button onclick="reconfigureSelected()" class="text-xs px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors font-medium"><?= t('supervision.btn_reconfigure_selected') ?></button>
                    <button onclick="detectVersionSelected()" class="text-xs px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('supervision.btn_detect_version_selected') ?></button>
                    <button onclick="scanAllAgents()" class="text-xs px-3 py-1.5 rounded-lg border border-indigo-300 dark:border-indigo-700 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 transition-colors"><?= t('supervision.btn_scan_all_agents') ?></button>
                    <span class="flex-1"></span>
                    <input type="text" id="deploy-filter" placeholder="<?= t('supervision.filter_placeholder') ?>" oninput="filterDeployTable()"
                           class="text-xs px-3 py-1.5 w-48 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-gray-200 focus:ring-1 focus:ring-blue-500">
                </div>

                <div class="overflow-x-auto max-h-[500px] overflow-y-auto scroll-smooth">
                    <table class="w-full table-auto text-sm">
                        <thead class="bg-gray-50 dark:bg-gray-700 text-xs uppercase text-gray-500 dark:text-gray-400 sticky top-0 z-10">
                            <tr>
                                <th class="p-2 w-10"></th>
                                <th class="p-2 text-left"><?= t('supervision.th_name') ?></th>
                                <th class="p-2"><?= t('supervision.th_ip') ?></th>
                                <th class="p-2"><?= t('supervision.th_env') ?></th>
                                <th class="p-2">Agents</th>
                                <th class="p-2"><?= t('supervision.th_status') ?></th>
                                <th class="p-2"><?= t('supervision.th_actions') ?></th>
                            </tr>
                        </thead>
                        <tbody id="deploy-table-body">
                            <?php
                            $badgeColors = [
                                'zabbix' => 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
                                'centreon' => 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
                                'prometheus' => 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300',
                                'telegraf' => 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
                            ];
                            $badgeLetters = ['zabbix' => 'Z', 'centreon' => 'C', 'prometheus' => 'P', 'telegraf' => 'T'];
                            foreach ($machines as $m):
                                $mid = (int)$m['id'];
                                $machineAgents = $agentsMap[$mid] ?? [];
                            ?>
                            <tr class="border-b border-gray-200 dark:border-gray-700" data-machine-id="<?= $mid ?>">
                                <td class="p-2 text-center">
                                    <input type="checkbox" name="deploy_machines[]" value="<?= $mid ?>" class="form-checkbox h-4 w-4 text-purple-600">
                                </td>
                                <td class="p-2 font-semibold deploy-name"><?= htmlspecialchars($m['name']) ?></td>
                                <td class="p-2 text-center text-xs"><?= htmlspecialchars($m['ip']) ?>:<?= htmlspecialchars($m['port']) ?></td>
                                <td class="p-2 text-center text-xs"><?= htmlspecialchars($m['environment'] ?? 'OTHER') ?></td>
                                <td class="p-2 text-center deploy-agents" data-machine-id="<?= $mid ?>">
                                    <?php if (empty($machineAgents)): ?>
                                        <span class="text-xs text-gray-400">-</span>
                                    <?php else: ?>
                                        <div class="flex flex-wrap gap-1 justify-center">
                                        <?php foreach ($machineAgents as $plat => $ag): ?>
                                            <span class="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-bold <?= $badgeColors[$plat] ?? '' ?>">
                                                <?= $badgeLetters[$plat] ?? '?' ?><?php if ($ag['agent_version']): ?> <?= htmlspecialchars($ag['agent_version']) ?><?php endif; ?>
                                            </span>
                                        <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                                <td class="p-2 text-center deploy-online-status text-xs">
                                    <?= htmlspecialchars($m['online_status'] ?? '-') ?>
                                </td>
                                <td class="p-2 text-center space-x-1 whitespace-nowrap">
                                    <button onclick="deploySingle(<?= $mid ?>)" class="deploy-action-btn text-xs px-2 py-1 bg-purple-500 hover:bg-purple-600 text-white rounded transition-colors"><?= t('supervision.btn_deploy') ?></button>
                                    <button onclick="reconfigureSingle(<?= $mid ?>)" class="text-xs px-2 py-1 bg-blue-500 hover:bg-blue-600 text-white rounded transition-colors"><?= t('supervision.btn_reconfigure') ?></button>
                                    <button onclick="uninstallAgent(<?= $mid ?>)" class="text-xs px-2 py-1 bg-red-500 hover:bg-red-600 text-white rounded transition-colors"><?= t('supervision.btn_uninstall') ?></button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Logs de deploiement -->
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm overflow-hidden">
                <div class="px-4 py-3 bg-gray-50 dark:bg-gray-700 border-b border-gray-200 dark:border-gray-600">
                    <h2 class="text-sm font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wide"><?= t('supervision.logs_title') ?></h2>
                </div>
                <div id="deploy-logs-container" class="logs-container"></div>
                <div id="deploy-logs" class="bg-gray-900 text-green-400 p-4 font-mono text-xs leading-relaxed h-48 overflow-y-auto whitespace-pre-line"></div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════════════════════════════════
             ONGLET 3 : Editeur de configuration
             ═══════════════════════════════════════════════════════════════════ -->
        <div id="tab-editor" class="tab-panel">
            <div class="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-4">
                <h2 class="text-lg font-bold mb-1"><?= t('supervision.editor_title') ?></h2>
                <p class="text-xs text-gray-400 mb-4"><?= t('supervision.editor_desc') ?></p>

                <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4 mb-4">
                    <div class="flex-1 w-full">
                        <label class="block text-sm font-medium mb-1"><?= t('supervision.editor_select_server') ?></label>
                        <select id="editor-server" class="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                            <option value=""><?= t('supervision.editor_select_server') ?></option>
                            <?php foreach ($machines as $s): ?>
                            <option value="<?= (int)$s['id'] ?>"><?= htmlspecialchars($s['name']) ?> (<?= htmlspecialchars($s['ip']) ?>)</option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <button onclick="loadRemoteConfig()" class="text-xs px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"><?= t('supervision.btn_load_config') ?></button>
                    <button onclick="saveRemoteConfig()" class="text-xs px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors font-medium"><?= t('supervision.btn_save_remote') ?></button>
                    <button onclick="loadBackups()" class="text-xs px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"><?= t('supervision.btn_backups') ?></button>
                </div>

                <div id="editor-file-badge" class="mb-2 text-xs">
                    <span class="text-gray-400"><?= t('supervision.config_file_path') ?></span>
                    <span id="editor-file-path-badge" class="ml-1 px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-700 font-mono text-gray-600 dark:text-gray-300">/etc/zabbix/zabbix_agent2.conf</span>
                </div>

                <textarea id="editor-content" rows="25"
                          class="w-full px-4 py-3 text-sm font-mono border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-200 leading-relaxed"
                          placeholder="<?= t('supervision.editor_placeholder') ?>"></textarea>

                <div id="editor-path" class="text-xs text-gray-400 mt-1"></div>
            </div>

            <!-- Modal backups -->
            <div id="backups-modal" class="hidden fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center z-50">
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-lg w-full max-w-lg mx-4 p-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-bold"><?= t('supervision.backup_list_title') ?></h3>
                        <button onclick="closeBackupsModal()" class="text-gray-400 hover:text-gray-600 text-xl">&times;</button>
                    </div>
                    <div id="backups-list" class="space-y-2 max-h-80 overflow-y-auto"></div>
                </div>
            </div>
        </div>

    </div>

    <script src="/supervision/js/main.js?v=<?= filemtime(__DIR__ . '/js/main.js') ?>"></script>
    <script src="/supervision/js/profiles.js?v=<?= file_exists(__DIR__ . '/js/profiles.js') ? filemtime(__DIR__ . '/js/profiles.js') : 0 ?>"></script>
    <?php require_once __DIR__ . '/../footer.php'; ?>
</body>
</html>
