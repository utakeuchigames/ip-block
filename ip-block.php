<?php
/**
 * Plugin Name: IP Block & Rate Limiter Manager
 * Plugin URI:  https://github.com/utakeuchigames/ip-block
 * Description: 高度なIPブロック、例外パス、レートリミット監視および管理画面機能を提供するセキュリティプラグインです。
 * Version:     1.0.7
 * Requires at least: 7.0
 * Tested up to: 7.1.4
 * Author:      utakeuchigames
 * Author URI:  https://github.com/utakeuchigames
 * License:     GPL2
 * Text Domain: ip-block
 */

if (!defined('ABSPATH')) {
    exit;
}

$upload_dir = wp_upload_dir();
if (!defined('IP_BLOCK_DATA_DIR')) {
    define('IP_BLOCK_DATA_DIR', $upload_dir['basedir'] . '/ip-block-data/');
}

// === muモード時のフラグ事前チェック（フラグが立っていなければ関数を作らずに終了） ===
$mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
if (strpos(__FILE__, $mu_dir) === 0) {
    $configFile = IP_BLOCK_DATA_DIR . '.config.php';
    $mu_mode_active = false;
    if (file_exists($configFile)) {
        $config_content = file_get_contents($configFile);
        if (preg_match('/MU_PLUGIN_MODE\s*=\s*1/', $config_content)) {
            $mu_mode_active = true;
        }
    }
    if (!$mu_mode_active) {
        return; // フラグが立っていないので関数もフックも一切登録しない
    }
}

if (!defined('URL_ROOT')) {
    define('URL_ROOT', plugin_dir_path(__FILE__));
}

if (!file_exists(IP_BLOCK_DATA_DIR)) {
    wp_mkdir_p(IP_BLOCK_DATA_DIR);
}

/**
 * 設定ファイル(.php)から設定値を取得する関数
 */
if (!function_exists('ip_block_get_config')) {
    function ip_block_get_config() {
        $configFile = IP_BLOCK_DATA_DIR . '.config.php';
        $config = [
            'limit_count' => 5,
            'time_window' => 1.0,
            'cloudflare_mode' => 0,
            'server_meip' => '',
            'login_limit_count' => 5,
            'mu_plugin_mode' => 0,
        ];

        if (file_exists($configFile)) {
            $lines = file($configFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#' || strpos($line, '<?php') !== false || strpos($line, 'exit') !== false) continue;
                if (strpos($line, '=') !== false) {
                    list($key, $val) = explode('=', $line, 2);
                    $key = strtolower(trim($key));
                    $val = trim($val);
                    if ($key === 'limit_count') {
                        $config['limit_count'] = max(1, (int)$val);
                    } elseif ($key === 'time_window') {
                        $config['time_window'] = max(0.1, (float)$val);
                    } elseif ($key === 'cloudflare_mode') {
                        $config['cloudflare_mode'] = (int)$val;
                    } elseif ($key === 'server_meip') {
                        $config['server_meip'] = $val;
                    } elseif ($key === 'login_limit_count') {
                        $config['login_limit_count'] = max(1, (int)$val);
                    } elseif ($key === 'mu_plugin_mode') {
                        $config['mu_plugin_mode'] = (int)$val;
                    }
                }
            }
        }
        return $config;
    }
}

/**
 * 設定を保存する関数
 */
if (!function_exists('ip_block_save_config')) {
    function ip_block_save_config($config) {
        $configFile = IP_BLOCK_DATA_DIR . '.config.php';
        $content = "<?php exit; ?>\n";
        $content .= "LIMIT_COUNT=" . (int)$config['limit_count'] . "\n";
        $content .= "TIME_WINDOW=" . (float)$config['time_window'] . "\n";
        $content .= "CLOUDFLARE_MODE=" . (int)$config['cloudflare_mode'] . "\n";
        $content .= "SERVER_MEIP=" . sanitize_text_field($config['server_meip']) . "\n";
        $content .= "LOGIN_LIMIT_COUNT=" . (int)$config['login_limit_count'] . "\n";
        $content .= "MU_PLUGIN_MODE=" . (int)$config['mu_plugin_mode'] . "\n";
        file_put_contents($configFile, $content, LOCK_EX);
    }
}

/**
 * 自作の ip-get.php を叩いてサーバー自身のグローバルIPを自動取得する関数
 */
if (!function_exists('ip_block_get_server_meip')) {
    function ip_block_get_server_meip() {
        $config = ip_block_get_config();

        if (!empty($config['server_meip']) && filter_var($config['server_meip'], FILTER_VALIDATE_IP)) {
            return $config['server_meip'];
        }

        $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        if (strpos(__FILE__, $mu_dir) === 0) {
            $my_ip_endpoint = content_url('mu-plugins/src/ip-get.php');
        } else {
            $my_ip_endpoint = plugins_url('src/ip-get.php', __FILE__);
        }

        $response = wp_remote_get($my_ip_endpoint, ['timeout' => 3, 'sslverify' => false]);
        $detected_ip = '';

        if (!is_wp_error($response)) {
            $body = trim(wp_remote_retrieve_body($response));
            
            $json_data = json_decode($body, true);
            if (!$json_data) {
                $fixed_body = str_replace("'", '"', $body);
                $json_data = json_decode($fixed_body, true);
            }

            if (!empty($json_data['ip']) && filter_var($json_data['ip'], FILTER_VALIDATE_IP)) {
                $detected_ip = $json_data['ip'];
            } elseif (filter_var($body, FILTER_VALIDATE_IP)) {
                $detected_ip = $body;
            }
        }

        if (empty($detected_ip)) {
            $detected_ip = $_SERVER['SERVER_ADDR'] ?? '127.0.0.1';
        }

        $config['server_meip'] = $detected_ip;
        ip_block_save_config($config);

        return $detected_ip;
    }
}

if (!defined('IP_BLOCK_SERVER_MEIP')) {
    define('IP_BLOCK_SERVER_MEIP', ip_block_get_server_meip());
}

/**
 * GitHubアクセストークンを取得する関数
 */
if (!function_exists('ip_block_get_github_token')) {
    function ip_block_get_github_token() {
        $tokenFile = IP_BLOCK_DATA_DIR . '.token.php';
        if (!file_exists($tokenFile)) return '';

        $lines = file($tokenFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) {
                continue;
            }
            return $trimmed;
        }
        return '';
    }
}

// 1. Plugin Update Checker (v5/v6対応) の組み込み
if (file_exists(__DIR__ . '/plugin-update-checker/plugin-update-checker.php')) {
    require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';
    
    $github_token = ip_block_get_github_token();

    if (class_exists('YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
        $myUpdateChecker = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            'https://github.com/utakeuchigames/ip-block',
            __FILE__,
            'ip-block'
        );
        $myUpdateChecker->setBranch('main');
        if (!empty($github_token)) {
            $myUpdateChecker->setAuthentication($github_token);
        }
    } elseif (class_exists('YahnisElsts\PluginUpdateChecker\v6\PucFactory')) {
        $myUpdateChecker = YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
            'https://github.com/utakeuchigames/ip-block',
            __FILE__,
            'ip-block'
        );
        $myUpdateChecker->setBranch('main');
        if (!empty($github_token)) {
            $myUpdateChecker->setAuthentication($github_token);
        }
    }
}

/**
 * 設定ファイル(.php)から有効なルールだけを抽出する関数
 */
if (!function_exists('parse_env_file_rules')) {
    function parse_env_file_rules($filepath) {
        if (!file_exists($filepath)) return [];
        
        $lines = file($filepath, FILE_IGNORE_NEW_LINES);
        if ($lines === false) return [];

        $rules = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) {
                continue;
            }
            $rules[] = $trimmed;
        }
        return $rules;
    }
}

/**
 * IPアドレスまたはCIDRにマッチするか判定
 */
if (!function_exists('ip_in_cidr')) {
    function ip_in_cidr($ip, $range) {
        if ($ip === $range) {
            return true;
        }
        if (strpos($range, '/') === false) {
            return false;
        }
        list($subnet, $bits) = explode('/', $range);
        $bits = (int)$bits;
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $ip = long2ip(ip2long($ip));
        $subnet = long2ip(ip2long($subnet));
        if ($ip === false || $subnet === false) {
            return false;
        }
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = ($bits === 0) ? 0 : (~0 << (32 - $bits));
        $subnet_long &= $mask;
        return ($ip_long & $mask) === $subnet_long;
    }
}

/**
 * ホワイトリストチェック
 */
if (!function_exists('check_white_list')) {
    function check_white_list($ip) {
        if ($ip === IP_BLOCK_SERVER_MEIP) {
            return true;
        }

        $whiteFile = IP_BLOCK_DATA_DIR . '.white.php';
        $rules = parse_env_file_rules($whiteFile);
        
        foreach ($rules as $range) {
            if (ip_in_cidr($ip, $range)) {
                return true;
            }
        }
        return false;
    }
}

/**
 * 厳密にホワイトリストに含まれているか（ボタン表示用）
 */
if (!function_exists('ip_block_is_in_whitelist')) {
    function ip_block_is_in_whitelist($ip) {
        $whiteFile = IP_BLOCK_DATA_DIR . '.white.php';
        $rules = parse_env_file_rules($whiteFile);
        foreach ($rules as $range) {
            if (ip_in_cidr($ip, $range)) {
                return true;
            }
        }
        return false;
    }
}

/**
 * ブロックリストチェック
 */
if (!function_exists('check_block_list')) {
    function check_block_list($ip) {
        $blockFile = IP_BLOCK_DATA_DIR . '.block.php';
        $rules = parse_env_file_rules($blockFile);
        
        foreach ($rules as $range) {
            if (ip_in_cidr($ip, $range)) {
                return true;
            }
        }
        return false;
    }
}

/**
 * ファイルにIPルールを安全に追記する共通関数（末尾改行を確実に保証）
 */
if (!function_exists('ip_block_append_to_file')) {
    function ip_block_append_to_file($filepath, $ip) {
        if ($ip === IP_BLOCK_SERVER_MEIP) return;

        $rules = parse_env_file_rules($filepath);

        $exists = false;
        foreach ($rules as $existing) {
            if (ip_in_cidr($ip, $existing)) {
                $exists = true;
                break;
            }
        }

        if (!$exists) {
            $rules[] = $ip;
            $content = "<?php exit; ?>\n" . implode("\n", $rules) . "\n";
            file_put_contents($filepath, $content, LOCK_EX);
        }
    }
}

/**
 * ファイルから特定のIP/ルールを削除する関数
 */
if (!function_exists('ip_block_remove_from_file')) {
    function ip_block_remove_from_file($filepath, $ip) {
        if (!file_exists($filepath)) return;

        $rules = parse_env_file_rules($filepath);
        $new_rules = [];
        foreach ($rules as $trimmed) {
            if ($trimmed === $ip || ip_in_cidr($ip, $trimmed)) {
                continue;
            }
            $new_rules[] = $trimmed;
        }

        $content = "<?php exit; ?>\n" . (empty($new_rules) ? "" : implode("\n", $new_rules) . "\n");
        file_put_contents($filepath, $content, LOCK_EX);
    }
}

/**
 * アクセス履歴（.history.php）から特定のIPの行を削除する関数
 */
if (!function_exists('ip_block_remove_history_ip')) {
    function ip_block_remove_history_ip($ip_to_remove) {
        $historyFile = IP_BLOCK_DATA_DIR . '.history.php';
        if (!file_exists($historyFile)) return;

        $lines = file($historyFile, FILE_IGNORE_NEW_LINES);
        if ($lines === false) return;

        $new_lines = ["<?php exit; ?>"];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) {
                continue;
            }
            $parts = explode(' ', $trimmed, 4);
            if (count($parts) >= 1 && $parts[0] !== $ip_to_remove) {
                $new_lines[] = $trimmed;
            }
        }

        file_put_contents($historyFile, implode("\n", $new_lines) . "\n", LOCK_EX);
    }
}

/**
 * ブロックリストへIPを追加して即終了する関数
 */
if (!function_exists('addBlockedIp')) {
    function addBlockedIp($ip, $file) {
        ip_block_append_to_file($file, $ip);
        ip_block_remove_from_file(IP_BLOCK_DATA_DIR . '.white.php', $ip);
        http_response_code(403);
        exit;
    }
}

// 2. アクセス制限・監視およびログイン失敗検知の実行コア処理
add_action('init', function() {
    global $accesscheck;
    if (!empty($accesscheck)) return;

    $config = ip_block_get_config();
    $limitCount = $config['limit_count'];      
    $timeWindow = $config['time_window'];      
    $cloudflareMode = $config['cloudflare_mode'];

    if ($cloudflareMode && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } else {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    if (check_white_list($clientIp)) {
        $accesscheck = true;
    }

    if (check_block_list($clientIp)) {
        http_response_code(403);
        exit;
    }

    // === 例外パス（スキップ対象）のチェック ===
    $exceptionFile = IP_BLOCK_DATA_DIR . '.exception.php';
    if (file_exists($exceptionFile)) {
        $exceptions = parse_env_file_rules($exceptionFile);
        $currentPath = $_SERVER['PHP_SELF'];
        
        foreach ($exceptions as $exPattern) {
            $exPattern = trim($exPattern);
            if ($exPattern === '' || $exPattern[0] === '#') continue;

            $pattern = '@^' . str_replace('\*', '.*', preg_quote($exPattern, '@')) . '$@i';
            if (preg_match($pattern, $currentPath)) {
                $accesscheck = true;
                return;
            }
        }
    }

    $currentTime = microtime(true);
    $currentUri = $_SERVER['REQUEST_URI'];
    $accessFile = IP_BLOCK_DATA_DIR . '.access.php';

    // --- A. レートリミット監視 (.access.php) ---
    $accessData = [];
    if (file_exists($accessFile)) {
        $lines = file($accessFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) continue;
            $parts = explode(' ', $trimmed, 3);
            if (count($parts) < 3) continue;
            list($ip, $timestamp, $count) = $parts;
            $accessData[$ip] = ['timestamp' => (float)$timestamp, 'count' => (int)$count];
        }
    }

    $newAccessData = [];
    foreach ($accessData as $ip => $data) {
        if (($currentTime - $data['timestamp']) < $timeWindow) {
            $newAccessData[$ip] = $data;
        }
    }

    if (isset($newAccessData[$clientIp])) {
        if ($newAccessData[$clientIp]['count'] >= $limitCount) {
            addBlockedIp($clientIp, IP_BLOCK_DATA_DIR . '.block.php');
        }
        $newAccessData[$clientIp]['count']++;
    } else {
        $newAccessData[$clientIp] = [
            'timestamp' => $currentTime,
            'count' => 1
        ];
    }

    $accessOutput = ["<?php exit; ?>"];
    foreach ($newAccessData as $ip => $data) {
        $accessOutput[] = "{$ip} {$data['timestamp']} {$data['count']}";
    }
    file_put_contents($accessFile, implode("\n", $accessOutput) . "\n", LOCK_EX);

    // --- B. アクセス履歴・統計保存 (.history.php) ---
    $historyFile = IP_BLOCK_DATA_DIR . '.history.php';
    $historyData = [];
    if (file_exists($historyFile)) {
        $lines = file($historyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) continue;
            $parts = explode(' ', $trimmed, 4);
            if (count($parts) < 4) continue;
            list($ip, $timestamp, $count, $lastfile) = $parts;
            $historyData[$ip] = [
                'timestamp' => (float)$timestamp,
                'count' => (int)$count,
                'lastfile' => $lastfile
            ];
        }
    }

    if (isset($historyData[$clientIp])) {
        $historyData[$clientIp]['count']++;
        $historyData[$clientIp]['timestamp'] = $currentTime;
        $historyData[$clientIp]['lastfile'] = $currentUri;
    } else {
        $historyData[$clientIp] = [
            'timestamp' => $currentTime,
            'count' => 1,
            'lastfile' => $currentUri
        ];
    }

    $historyOutput = ["<?php exit; ?>"];
    foreach ($historyData as $ip => $data) {
        $historyOutput[] = "{$ip} {$data['timestamp']} {$data['count']} {$data['lastfile']}";
    }
    file_put_contents($historyFile, implode("\n", $historyOutput) . "\n", LOCK_EX);
    
    if (check_white_list($clientIp)) {
        return;
    }
    $accesscheck = true;
});

// --- 3. ログイン失敗検知および成功時リセットのフック処理 ---
add_action('wp_login_failed', function($username) {
    $config = ip_block_get_config();
    $loginLimitCount = $config['login_limit_count'];
    $cloudflareMode = $config['cloudflare_mode'];

    if ($cloudflareMode && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } else {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    if (check_white_list($clientIp) || $clientIp === IP_BLOCK_SERVER_MEIP) {
        return;
    }

    $failFile = IP_BLOCK_DATA_DIR . '.login-fails.php';
    $currentTime = time();
    $failsData = [];

    if (file_exists($failFile)) {
        $lines = file($failFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) continue;
            $parts = explode(' ', $trimmed, 3);
            if (count($parts) < 3) continue;
            list($ip, $timestamp, $count) = $parts;
            $failsData[$ip] = ['timestamp' => (int)$timestamp, 'count' => (int)$count];
        }
    }

    if (isset($failsData[$clientIp])) {
        $failsData[$clientIp]['count']++;
        $failsData[$clientIp]['timestamp'] = $currentTime;
    } else {
        $failsData[$clientIp] = [
            'timestamp' => $currentTime,
            'count' => 1
        ];
    }

    if ($failsData[$clientIp]['count'] >= $loginLimitCount) {
        ip_block_append_to_file(IP_BLOCK_DATA_DIR . '.block.php', $clientIp);
        ip_block_remove_from_file(IP_BLOCK_DATA_DIR . '.white.php', $clientIp);
        unset($failsData[$clientIp]);
    }

    $failOutput = ["<?php exit; ?>"];
    foreach ($failsData as $ip => $data) {
        $failOutput[] = "{$ip} {$data['timestamp']} {$data['count']}";
    }
    file_put_contents($failFile, implode("\n", $failOutput) . "\n", LOCK_EX);
});

add_action('wp_login', function($user_login, $user) {
    $cloudflareMode = ip_block_get_config()['cloudflare_mode'];
    if ($cloudflareMode && !empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $clientIp = $_SERVER['HTTP_CF_CONNECTING_IP'];
    } else {
        $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    $failFile = IP_BLOCK_DATA_DIR . '.login-fails.php';
    if (!file_exists($failFile)) return;

    $lines = file($failFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $failsData = [];
    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) continue;
        $parts = explode(' ', $trimmed, 3);
        if (count($parts) < 3) continue;
        list($ip, $timestamp, $count) = $parts;
        if ($ip !== $clientIp) {
            $failsData[$ip] = ['timestamp' => (int)$timestamp, 'count' => (int)$count];
        }
    }

    $failOutput = ["<?php exit; ?>"];
    foreach ($failsData as $ip => $data) {
        $failOutput[] = "{$ip} {$data['timestamp']} {$data['count']}";
    }
    file_put_contents($failFile, implode("\n", $failOutput) . "\n", LOCK_EX);
}, 10, 2);

// 4. WordPress管理画面の設定メニューおよびサブメニュー追加
add_action('admin_menu', function() {
    add_menu_page(
        'IP Block 管理',
        'IP Block',
        'manage_options',
        'ip-block-manage',
        'ip_block_dashboard_page_html',
        'dashicons-shield',
        80
    );

    add_submenu_page(
        'ip-block-manage',
        'アクセス監視',
        'アクセス監視',
        'manage_options',
        'ip-block-manage',
        'ip_block_dashboard_page_html'
    );

    add_submenu_page(
        'ip-block-manage',
        '詳細設定',
        '詳細設定',
        'manage_options',
        'ip-block-settings',
        'ip_block_settings_page_html'
    );

    add_submenu_page(
        'ip-block-manage',
        'ブロックリスト',
        'ブロックリスト',
        'manage_options',
        'ip-block-blacklist',
        'ip_block_blacklist_page_html'
    );

    add_submenu_page(
        'ip-block-manage',
        'ホワイトリスト',
        'ホワイトリスト',
        'manage_options',
        'ip-block-whitelist',
        'ip_block_whitelist_page_html'
    );

    add_submenu_page(
        'ip-block-manage',
        '例外パス',
        '例外パス',
        'manage_options',
        'ip-block-exceptions',
        'ip_block_exceptions_page_html'
    );
});

// --- 各サブメニューのページ描画関数 ---

// 1. アクセス監視ダッシュボード
if (!function_exists('ip_block_dashboard_page_html')) {
    function ip_block_dashboard_page_html() {
        if (!current_user_can('manage_options')) return;

        if (isset($_POST['ip_action']) && isset($_POST['target_ip'])) {
            check_admin_referer('ip_block_action_nonce_action', 'ip_block_action_nonce');
            $target_ip = sanitize_text_field($_POST['target_ip']);
            $action_type = sanitize_text_field($_POST['ip_action']);

            if (filter_var($target_ip, FILTER_VALIDATE_IP)) {
                if ($action_type === 'block') {
                    ip_block_append_to_file(IP_BLOCK_DATA_DIR . '.block.php', $target_ip);
                    ip_block_remove_from_file(IP_BLOCK_DATA_DIR . '.white.php', $target_ip);
                    ip_block_remove_history_ip($target_ip);
                    echo '<div class="updated"><p><strong>IP <code>' . esc_html($target_ip) . '</code> をブロックリストに追加し、ホワイトリストから除外してアクセス履歴から削除しました。</strong></p></div>';
                } elseif ($action_type === 'whitelist_add') {
                    ip_block_append_to_file(IP_BLOCK_DATA_DIR . '.white.php', $target_ip);
                    echo '<div class="updated"><p><strong>IP <code>' . esc_html($target_ip) . '</code> をホワイトリストに追加しました（アクセス履歴は保持されます）。</strong></p></div>';
                } elseif ($action_type === 'whitelist_remove') {
                    ip_block_remove_from_file(IP_BLOCK_DATA_DIR . '.white.php', $target_ip);
                    echo '<div class="updated"><p><strong>IP <code>' . esc_html($target_ip) . '</code> をホワイトリストから外しました。</strong></p></div>';
                }
            }
        }

        $historyFile = IP_BLOCK_DATA_DIR . '.history.php';
        $config = ip_block_get_config();

        $active_accesses = [];
        if (file_exists($historyFile)) {
            $lines = file($historyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $trimmed = trim($line);
                if ($trimmed === '' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) continue;
                $parts = explode(' ', $trimmed, 4);
                if (count($parts) >= 4) {
                    list($ip, $timestamp, $count, $lastfile) = $parts;
                    
                    if ($ip === IP_BLOCK_SERVER_MEIP) {
                        continue; 
                    }

                    $active_accesses[] = [
                        'ip' => $ip,
                        'timestamp' => (float)$timestamp,
                        'count' => (int)$count,
                        'lastfile' => $lastfile
                    ];
                }
            }
        }
        ?>
        <div class="wrap">
            <h1>🛡️ IP Block ダッシュボード (アクセス監視)</h1>
            <p>現在のレートリミット設定： <strong><?php echo (int)$config['time_window']; ?>秒</strong> の間に <strong><?php echo (int)$config['limit_count']; ?>回</strong> 以上のアクセスで自動ブロック</p>
            <p>現在のログイン失敗制限： <strong><?php echo (int)$config['login_limit_count']; ?>回</strong> 間違えると自動ブロック</p>
            <p><strong>サーバー自身のIP（自動除外中）:</strong> <code><?php echo esc_html(IP_BLOCK_SERVER_MEIP); ?></code></p>
            
            <h2>📊 記録されているアクセス履歴</h2>
            <table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">
                <thead>
                    <tr>
                        <th>IPアドレス</th>
                        <th>総アクセス回数</th>
                        <th>最終アクセス日時</th>
                        <th>直近アクセス先</th>
                        <th style="width: 260px;">アクション</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($active_accesses)): ?>
                        <tr><td colspan="5">現在記録されている外部のアクセスはありません。</td></tr>
                    <?php else: ?>
                        <?php foreach ($active_accesses as $acc): ?>
                            <?php $is_whitelisted = ip_block_is_in_whitelist($acc['ip']); ?>
                            <tr>
                                <td><code><?php echo esc_html($acc['ip']); ?></code></td>
                                <td><?php echo (int)$acc['count']; ?> 回</td>
                                <td><?php echo esc_html(date('Y-m-d H:i:s', (int)$acc['timestamp'])); ?></td>
                                <td><small><?php echo esc_html($acc['lastfile']); ?></small></td>
                                <td>
                                    <form method="post" action="" style="display:inline;">
                                        <?php wp_nonce_field('ip_block_action_nonce_action', 'ip_block_action_nonce'); ?>
                                        <input type="hidden" name="target_ip" value="<?php echo esc_attr($acc['ip']); ?>">
                                        <button type="submit" name="ip_action" value="block" class="button button-small button-link-delete" onclick="return confirm('本当にこのIPをブロックしますか？');">ブロック</button>
                                    </form>
                                    <?php if ($is_whitelisted): ?>
                                        <form method="post" action="" style="display:inline; margin-left: 5px;">
                                            <?php wp_nonce_field('ip_block_action_nonce_action', 'ip_block_action_nonce'); ?>
                                            <input type="hidden" name="target_ip" value="<?php echo esc_attr($acc['ip']); ?>">
                                            <button type="submit" name="ip_action" value="whitelist_remove" class="button button-small button-primary">ホワイトリストに入れてあります</button>
                                        </form>
                                    <?php else: ?>
                                        <form method="post" action="" style="display:inline; margin-left: 5px;">
                                            <?php wp_nonce_field('ip_block_action_nonce_action', 'ip_block_action_nonce'); ?>
                                            <input type="hidden" name="target_ip" value="<?php echo esc_attr($acc['ip']); ?>">
                                            <button type="submit" name="ip_action" value="whitelist_add" class="button button-small">ホワイトリスト</button>
                                        </form>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            <p style="margin-top: 20px;"><small>Wordfenceなどのセキュリティプラグインと併用している場合、動作に支障をきたす事がございます。</small></p>
        </div>
        <?php
    }
}

// 2. 詳細設定画面
if (!function_exists('ip_block_settings_page_html')) {
    function ip_block_settings_page_html() {
        if (!current_user_can('manage_options')) return;
        $configFile = IP_BLOCK_DATA_DIR . '.config.php';
        $tokenFile = IP_BLOCK_DATA_DIR . '.token.php';

        $is_hidden_mode = isset($_GET['secret']) && $_GET['secret'] === 'token';

        if (isset($_POST['ip_block_submit'])) {
            check_admin_referer('ip_block_settings_nonce');
            
            $config = ip_block_get_config();
            $config['limit_count'] = max(1, (int)$_POST['limit_count']);
            $config['time_window'] = max(0.1, (float)$_POST['time_window']);
            $config['cloudflare_mode'] = isset($_POST['cloudflare_mode']) ? 1 : 0;
            $config['login_limit_count'] = max(1, (int)$_POST['login_limit_count']);
            
            $new_mu_mode = isset($_POST['mu_plugin_mode']) ? 1 : 0;
            $config['mu_plugin_mode'] = $new_mu_mode;
            
            ip_block_save_config($config);

            $mu_dir = defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
            if (!file_exists($mu_dir)) {
                wp_mkdir_p($mu_dir);
            }
            $target_mu_file = $mu_dir . '/ip-block.php';
            
            $mu_src_dir = $mu_dir . '/src';
            $source_src_dir = __DIR__ . '/src';

            if ($new_mu_mode === 1) {
                $source_code = file_get_contents(__FILE__);
                $modified_code = str_replace(
                    'Plugin Name: IP Block & Rate Limiter Manager',
                    'Plugin Name: IP Block & Rate Limiter Manager (mu mode)',
                    $source_code
                );
                file_put_contents($target_mu_file, $modified_code, LOCK_EX);

                if (!file_exists($mu_src_dir)) {
                    wp_mkdir_p($mu_src_dir);
                }
                if (file_exists($source_src_dir . '/ip-get.php')) {
                    copy($source_src_dir . '/ip-get.php', $mu_src_dir . '/ip-get.php');
                }

                if (is_plugin_active('ip-block/ip-block.php')) {
                    deactivate_plugins('ip-block/ip-block.php');
                }
            } else {
                if (file_exists($target_mu_file)) {
                    @unlink($target_mu_file);
                }
                if (file_exists($mu_src_dir . '/ip-get.php')) {
                    @unlink($mu_src_dir . '/ip-get.php');
                }
                if (file_exists($mu_src_dir)) {
                    @rmdir($mu_src_dir);
                }

                if (!is_plugin_active('ip-block/ip-block.php')) {
                    activate_plugin('ip-block/ip-block.php');
                }
            }

            if ($is_hidden_mode && isset($_POST['github_token'])) {
                $github_token = sanitize_text_field($_POST['github_token']);
                $newTokenData = "<?php exit; ?>\n" . $github_token . "\n";
                file_put_contents($tokenFile, $newTokenData, LOCK_EX);
            }

            echo '<div class="updated"><p><strong>詳細設定を保存しました！</strong></p></div>';
        }

        $config = ip_block_get_config();
        $current_token = ip_block_get_github_token();
        ?>
        <div class="wrap">
            <h1>⚙️ 詳細設定</h1>
            <form method="post" action="">
                <?php wp_nonce_field('ip_block_settings_nonce'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="limit_count">制限回数 (回)</label></th>
                        <td>
                            <input name="limit_count" type="number" id="limit_count" value="<?php echo esc_attr($config['limit_count']); ?>" min="1" max="100" class="small-text" required>
                            <p class="description">指定した制限時間内に、この回数を超えてアクセスするとブロックリストに自動追加されます。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="time_window">制限時間 (秒)</label></th>
                        <td>
                            <input name="time_window" type="number" step="0.1" id="time_window" value="<?php echo esc_attr($config['time_window']); ?>" min="0.1" max="60" class="small-text" required>
                            <p class="description">この秒数内のアクセスをカウントします（例: 1.0秒なら1秒間に何回アクセスされたか）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="login_limit_count">ログイン失敗制限 (回)</label></th>
                        <td>
                            <input name="login_limit_count" type="number" id="login_limit_count" value="<?php echo esc_attr($config['login_limit_count']); ?>" min="1" max="20" class="small-text" required>
                            <p class="description">ログインをこの回数連続で失敗すると、そのIPからのアクセスを自動的にブロックします（成功するとカウントはリセットされます）。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Cloudflare対応モード</th>
                        <td>
                            <label for="cloudflare_mode">
                                <input name="cloudflare_mode" type="checkbox" id="cloudflare_mode" value="1" <?php checked($config['cloudflare_mode'], 1); ?>>
                                Cloudflare経由のアクセス元IP（<code>HTTP_CF_CONNECTING_IP</code>）を優先して取得する
                            </label>
                            <p class="description">Cloudflareを使用している環境で有効にしてください。</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">素早くブロック (mu-pluginsモード)</th>
                        <td>
                            <label for="mu_plugin_mode">
                                <input name="mu_plugin_mode" type="checkbox" id="mu_plugin_mode" value="1" <?php checked($config['mu_plugin_mode'], 1); ?>>
                                ONにすると自動配置＆通常版停止。OFFにすると自動削除＆通常版が自動で再起動（有効化）されます
                            </label>
                            <p class="description">有効にするとWordfenceなどの検知よりも手前で門前払いが可能になります。</p>
                        </td>
                    </tr>

                    <?php if ($is_hidden_mode): ?>
                    <tr style="background: #fff8e5; border-left: 4px solid #ffb900;">
                        <th scope="row"><label for="github_token">🔓 [隠し機能] GitHub トークン</label></th>
                        <td>
                            <input name="github_token" type="password" id="github_token" value="<?php echo esc_attr($current_token); ?>" class="regular-text" placeholder="ghp_xxxx または github_pat_xxxx">
                            <p class="description">裏モードで有効なAPIレートリミット回避用トークンです。</p>
                        </td>
                    </tr>
                    <?php endif; ?>

                </table>
                <?php submit_button('設定を保存する', 'primary', 'ip_block_submit', true); ?>
            </form>
        </div>
        <?php
    }
}

// 3. ブロックリスト設定画面
if (!function_exists('ip_block_blacklist_page_html')) {
    function ip_block_blacklist_page_html() {
        if (!current_user_can('manage_options')) return;
        $blockFile = IP_BLOCK_DATA_DIR . '.block.php';

        if (isset($_POST['ip_block_submit'])) {
            check_admin_referer('ip_block_blacklist_nonce');
            if (isset($_POST['block_content'])) {
                $raw_content = wp_unslash($_POST['block_content']);
                $rules = [];
                foreach (explode("\n", $raw_content) as $line) {
                    $t = trim($line);
                    if ($t !== '' && strpos($t, '<?php') === false && strpos($t, 'exit') === false) {
                        $rules[] = $t;
                    }
                }
                $final_content = "<?php exit; ?>\n" . (empty($rules) ? "" : implode("\n", $rules) . "\n");
                file_put_contents($blockFile, $final_content, LOCK_EX);
                echo '<div class="updated"><p><strong>ブロックリストを保存しました！</strong></p></div>';
            }
        }
        $block_rules = parse_env_file_rules($blockFile);
        $block_data = implode("\n", $block_rules);
        ?>
        <div class="wrap">
            <h1>🚫 ブロックリスト設定 (.block.php)</h1>
            <form method="post" action="">
                <?php wp_nonce_field('ip_block_blacklist_nonce'); ?>
                <textarea name="block_content" rows="12" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($block_data); ?></textarea>
                <p style="margin-top: 15px;">
                    <?php submit_button('ブロックリストを保存する', 'primary', 'ip_block_submit', false); ?>
                </p>
            </form>
        </div>
        <?php
    }
}

// 4. ホワイトリスト設定画面
if (!function_exists('ip_block_whitelist_page_html')) {
    function ip_block_whitelist_page_html() {
        if (!current_user_can('manage_options')) return;
        $whiteFile = IP_BLOCK_DATA_DIR . '.white.php';

        if (isset($_POST['ip_block_submit'])) {
            check_admin_referer('ip_block_whitelist_nonce');
            if (isset($_POST['white_content'])) {
                $raw_content = wp_unslash($_POST['white_content']);
                $rules = [];
                foreach (explode("\n", $raw_content) as $line) {
                    $t = trim($line);
                    if ($t !== '' && strpos($t, '<?php') === false && strpos($t, 'exit') === false) {
                        $rules[] = $t;
                    }
                }
                $final_content = "<?php exit; ?>\n" . (empty($rules) ? "" : implode("\n", $rules) . "\n");
                file_put_contents($whiteFile, $final_content, LOCK_EX);
                echo '<div class="updated"><p><strong>ホワイトリストを保存しました！</strong></p></div>';
            }
        }
        $white_rules = parse_env_file_rules($whiteFile);
        $white_data = implode("\n", $white_rules);
        ?>
        <div class="wrap">
            <h1>⚪ ホワイトリスト設定 (.white.php)</h1>
            <form method="post" action="">
                <?php wp_nonce_field('ip_block_whitelist_nonce'); ?>
                <textarea name="white_content" rows="12" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($white_data); ?></textarea>
                <p style="margin-top: 15px;">
                    <?php submit_button('ホワイトリストを保存する', 'primary', 'ip_block_submit', false); ?>
                </p>
            </form>
        </div>
        <?php
    }
}

// 5. 例外パス設定画面
if (!function_exists('ip_block_exceptions_page_html')) {
    function ip_block_exceptions_page_html() {
        if (!current_user_can('manage_options')) return;
        $exceptionFile = IP_BLOCK_DATA_DIR . '.exception.php';

        if (isset($_POST['ip_block_submit'])) {
            check_admin_referer('ip_block_exceptions_nonce');
            if (isset($_POST['exception_content'])) {
                $raw_content = wp_unslash($_POST['exception_content']);
                $rules = [];
                foreach (explode("\n", $raw_content) as $line) {
                    $t = trim($line);
                    if ($t !== '' && strpos($t, '<?php') === false && strpos($t, 'exit') === false) {
                        $rules[] = $t;
                    }
                }
                $final_content = "<?php exit; ?>\n" . (empty($rules) ? "" : implode("\n", $rules) . "\n");
                file_put_contents($exceptionFile, $final_content, LOCK_EX);
                echo '<div class="updated"><p><strong>例外パス設定を保存しました！</strong></p></div>';
            }
        }
        $ex_rules = parse_env_file_rules($exceptionFile);
        $exception_data = implode("\n", $ex_rules);
        ?>
        <div class="wrap">
            <h1>⏩ 例外パス設定 (.exception.php)</h1>
            <form method="post" action="">
                <?php wp_nonce_field('ip_block_exceptions_nonce'); ?>
                <textarea name="exception_content" rows="12" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($exception_data); ?></textarea>
                <p style="margin-top: 15px;">
                    <?php submit_button('例外パスを保存する', 'primary', 'ip_block_submit', false); ?>
                </p>
            </form>
        </div>
        <?php
    }
}