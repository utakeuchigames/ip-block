<?php
/**
 * Plugin Name: IP Block & Rate Limiter Manager
 * Plugin URI:  https://github.com/utakeuchigames/ip-block
 * Description: 高度なIPブロック、例外パス、レートリミット監視および管理画面機能を提供するセキュリティプラグインです。
 * Version:     1.0.2
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

if (!defined('URL_ROOT')) {
    define('URL_ROOT', plugin_dir_path(__FILE__));
}

$server_ip = gethostbyname($_SERVER['SERVER_NAME'] ?? 'localhost');
define('IP_BLOCK_SERVER_MEIP', $server_ip);

$upload_dir = wp_upload_dir();
define('IP_BLOCK_DATA_DIR', $upload_dir['basedir'] . '/ip-block-data/');

if (!file_exists(IP_BLOCK_DATA_DIR)) {
    wp_mkdir_p(IP_BLOCK_DATA_DIR);
}

// 1. Plugin Update Checker (v5/v6対応) の組み込み
if (file_exists(__DIR__ . '/plugin-update-checker/plugin-update-checker.php')) {
    require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';
    
    if (class_exists('YahnisElsts\PluginUpdateChecker\v5\PucFactory')) {
        $myUpdateChecker = YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
            'https://github.com/utakeuchigames/ip-block',
            __FILE__,
            'ip-block'
        );
        $myUpdateChecker->setBranch('main');
    } elseif (class_exists('YahnisElsts\PluginUpdateChecker\v6\PucFactory')) {
        $myUpdateChecker = YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
            'https://github.com/utakeuchigames/ip-block',
            __FILE__,
            'ip-block'
        );
        $myUpdateChecker->setBranch('main');
    }
}

/**
 * 設定ファイル(.php)から有効なルールだけを抽出する関数
 */
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

/**
 * 詳細設定（レートリミット設定等）を取得する関数
 */
function ip_block_get_config() {
    $configFile = IP_BLOCK_DATA_DIR . '.config.php';
    $config = [
        'limit_count' => 5,
        'time_window' => 1.0,
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
                }
            }
        }
    }
    return $config;
}

/**
 * IPアドレスまたはCIDRにマッチするか判定
 */
function ip_in_cidr($ip, $range) {
    if ($ip === $range) {
        return true;
    }
    if (strpos($range, '/') === false) {
        return false;
    }
    list($subnet, $bits) = explode('/', $range);
    $ip = long2ip(ip2long($ip));
    $subnet = long2ip(ip2long($subnet));
    if ($ip === false || $subnet === false) {
        return false;
    }
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);
    $mask = -1 << (32 - (int)$bits);
    $subnet_long &= $mask;
    return ($ip_long & $mask) === $subnet_long;
}

/**
 * ホワイトリストチェック
 */
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

/**
 * 厳密にホワイトリストに含まれているか（ボタン表示用）
 */
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

/**
 * ブロックリストチェック
 */
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

/**
 * ファイルにIPルールを安全に追記する共通関数
 */
function ip_block_append_to_file($filepath, $ip) {
    if ($ip === IP_BLOCK_SERVER_MEIP) return;

    if (!file_exists($filepath) || filesize($filepath) === 0) {
        file_put_contents($filepath, "<?php exit; ?>\n" . $ip . "\n", LOCK_EX);
        return;
    }

    $currentIps = parse_env_file_rules($filepath);

    $exists = false;
    foreach ($currentIps as $existing) {
        if (ip_in_cidr($ip, $existing)) {
            $exists = true;
            break;
        }
    }

    if (!$exists) {
        file_put_contents($filepath, $ip . "\n", FILE_APPEND | LOCK_EX);
    }
}

/**
 * ファイルから特定のIP/ルールを削除する関数
 */
function ip_block_remove_from_file($filepath, $ip) {
    if (!file_exists($filepath)) return;

    $lines = file($filepath, FILE_IGNORE_NEW_LINES);
    if ($lines === false) return;

    $new_lines = ["<?php exit; ?>"];
    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || $trimmed[0] === '#' || strpos($trimmed, '<?php') !== false || strpos($trimmed, 'exit') !== false) {
            continue;
        }
        if ($trimmed === $ip || ip_in_cidr($ip, $trimmed)) {
            continue;
        }
        $new_lines[] = $trimmed;
    }

    file_put_contents($filepath, implode("\n", $new_lines) . "\n", LOCK_EX);
}

/**
 * アクセス履歴（.history.php）から特定のIPの行を削除する関数
 */
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

/**
 * ブロックリストへIPを追加して即終了する関数
 */
function addBlockedIp($ip, $file) {
    ip_block_append_to_file($file, $ip);
    ip_block_remove_from_file(IP_BLOCK_DATA_DIR . '.white.php', $ip);
    http_response_code(403);
    exit;
}

// 2. アクセス制限・監視の実行コア処理
add_action('init', function() {
    global $accesscheck;
    if (!empty($accesscheck)) return;

    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';

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

    $config = ip_block_get_config();
    $limitCount = $config['limit_count'];      
    $timeWindow = $config['time_window'];      
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

    // 古いデータの掃除と現在のIPのカウント更新
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

// 3. WordPress管理画面の設定メニューおよびサブメニュー追加
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
function ip_block_dashboard_page_html() {
    if (!current_user_can('manage_options')) return;

    // テーブル上のボタン処理
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

// 2. 詳細設定画面 (レートリミット等)
function ip_block_settings_page_html() {
    if (!current_user_can('manage_options')) return;
    $configFile = IP_BLOCK_DATA_DIR . '.config.php';

    if (isset($_POST['ip_block_submit'])) {
        check_admin_referer('ip_block_settings_nonce');
        $limit_count = max(1, (int)$_POST['limit_count']);
        $time_window = max(0.1, (float)$_POST['time_window']);

        $newConfigData = "<?php exit; ?>\nLIMIT_COUNT={$limit_count}\nTIME_WINDOW={$time_window}\n";
        file_put_contents($configFile, $newConfigData, LOCK_EX);
        echo '<div class="updated"><p><strong>詳細設定を保存しました！</strong></p></div>';
    }

    $config = ip_block_get_config();
    ?>
    <div class="wrap">
        <h1>⚙️ 詳細設定 (レートリミット調整)</h1>
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
            </table>
            <?php submit_button('設定を保存する', 'primary', 'ip_block_submit', true); ?>
        </form>
    </div>
    <?php
}

// 3. ブロックリスト設定画面
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
            $final_content = "<?php exit; ?>\n" . implode("\n", $rules) . "\n";
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

// 4. ホワイトリスト設定画面
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
            $final_content = "<?php exit; ?>\n" . implode("\n", $rules) . "\n";
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

// 5. 例外パス設定画面
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
            $final_content = "<?php exit; ?>\n" . implode("\n", $rules) . "\n";
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