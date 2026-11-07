<?php
/**
 * Plugin Name: IP Block & Rate Limiter Manager
 * Plugin URI:  https://github.com/utakeuchigames/ip-block
 * Description: 高度なIPブロック、例外パス、レートリミット監視および管理画面機能を提供するセキュリティプラグインです。
 * Version:     1.2.5
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
// サーバー自身のIPを固定で定義
define('IP_BLOCK_SERVER_MEIP', $server_ip);

// プラグインをアプデしてもデータが消えないよう、アップロードフォルダ内に専用のデータ保存ディレクトリを定義
$upload_dir = wp_upload_dir();
define('IP_BLOCK_DATA_DIR', $upload_dir['basedir'] . '/ip-block-data/');

// データ保存用ディレクトリがなければ自動作成する
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
 * 設定ファイルから有効なルールだけを抽出する関数
 */
function parse_env_file_rules($filepath) {
    if (!file_exists($filepath)) return [];
    
    $lines = file($filepath, FILE_IGNORE_NEW_LINES);
    if ($lines === false) return [];

    $has_marker = false;
    foreach ($lines as $line) {
        if (strpos(trim($line), '#/ Clients can configure settings from here.') !== false) {
            $has_marker = true;
            break;
        }
    }

    $rules = [];
    $start_reading = !$has_marker;

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (!$start_reading) {
            if (strpos($trimmed, '#/ Clients can configure settings from here.') !== false) {
                $start_reading = true;
            }
            continue;
        }

        if ($trimmed === '' || $trimmed[0] === '#') {
            continue;
        }
        $rules[] = $trimmed;
    }
    return $rules;
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

    $whiteFile = IP_BLOCK_DATA_DIR . '.white.env';
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
    $blockFile = IP_BLOCK_DATA_DIR . '.block.env';
    $rules = parse_env_file_rules($blockFile);
    
    foreach ($rules as $range) {
        if (ip_in_cidr($ip, $range)) {
            return true;
        }
    }
    return false;
}

/**
 * ブロックリストへIPを追加
 */
function addBlockedIp($ip, $file) {
    if ($ip === IP_BLOCK_SERVER_MEIP) {
        return;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        http_response_code(403);
        exit;
    }

    $currentIps = file_exists($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    $currentIps = array_map('trim', $currentIps);

    $exists = false;
    foreach ($currentIps as $existing) {
        if (ip_in_cidr($ip, $existing)) {
            $exists = true;
            break;
        }
    }

    if (!$exists) {
        $appendData = $ip;
        if (file_exists($file) && filesize($file) > 0) {
            $fp = fopen($file, 'r');
            fseek($fp, -1, SEEK_END);
            $lastChar = fgetc($fp);
            fclose($fp);

            if ($lastChar !== "\n" && $lastChar !== "\r") {
                $appendData = PHP_EOL . $ip;
            }
        }
        file_put_contents($file, $appendData, FILE_APPEND | LOCK_EX);
    }

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
        return;
    }

    if (check_block_list($clientIp)) {
        http_response_code(403);
        exit;
    }

    // === 例外パス（スキップ対象）のチェック ===
    $exceptionFile = IP_BLOCK_DATA_DIR . '.exception.env';
    if (file_exists($exceptionFile)) {
        $exceptions = file($exceptionFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
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

    // --- A. レートリミット処理 (.access.env) ---
    $limitCount = 5;       
    $timeWindow = 1.0;     
    $accessFile = IP_BLOCK_DATA_DIR . '.access.env';

    if (!file_exists($accessFile)) {
        file_put_contents($accessFile, "");
    }

    $fp = fopen($accessFile, 'r+');
    if (flock($fp, LOCK_EX)) {
        $clientData = null;
        $otherData = [];

        while (($line = fgets($fp)) !== false) {
            $line = trim($line);
            if ($line === '') continue;
            
            $parts = explode(' ', $line, 3);
            if (count($parts) < 3) continue;
            
            list($ip, $timestamp, $count) = $parts;
            $timestamp = (float)$timestamp;
            $count = (int)$count;
            
            if (($currentTime - $timestamp) < $timeWindow) {
                if ($ip === $clientIp) {
                    $clientData = ['timestamp' => $timestamp, 'count' => $count];
                } else {
                    $otherData[] = "{$ip} {$timestamp} {$count}";
                }
            }
        }

        if ($clientData !== null) {
            if ($clientData['count'] >= $limitCount) {
                flock($fp, LOCK_UN);
                fclose($fp);
                addBlockedIp($clientIp, IP_BLOCK_DATA_DIR . '.block.env');
                exit;
            }
            $newCount = $clientData['count'] + 1;
            $newTimestamp = $clientData['timestamp'];
        } else {
            $newCount = 1;
            $newTimestamp = $currentTime;
        }

        $otherData[] = "{$clientIp} {$newTimestamp} {$newCount}";

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, implode("\n", $otherData) . "\n");
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    // --- B. アクセス履歴・統計保存 (.history.env) ---
    $historyFile = IP_BLOCK_DATA_DIR . '.history.env';
    if (!file_exists($historyFile)) {
        file_put_contents($historyFile, "");
    }

    $fp_h = fopen($historyFile, 'r+');
    if (flock($fp_h, LOCK_EX)) {
        $historyData = [];
        $foundClient = false;

        while (($line = fgets($fp_h)) !== false) {
            $line = trim($line);
            if ($line === '') continue;
            
            $parts = explode(' ', $line, 4);
            if (count($parts) < 4) continue;
            
            list($ip, $timestamp, $count, $lastfile) = $parts;
            $timestamp = (float)$timestamp;
            $count = (int)$count;

            if ($ip === $clientIp) {
                $count++;
                $timestamp = $currentTime;
                $lastfile = $currentUri;
                $foundClient = true;
            }
            $historyData[] = "{$ip} {$timestamp} {$count} {$lastfile}";
        }

        if (!$foundClient) {
            $historyData[] = "{$clientIp} {$currentTime} 1 {$currentUri}";
        }

        ftruncate($fp_h, 0);
        rewind($fp_h);
        fwrite($fp_h, implode("\n", $historyData) . "\n");
        flock($fp_h, LOCK_UN);
        fclose($fp_h);
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

    $historyFile = IP_BLOCK_DATA_DIR . '.history.env';

    $active_accesses = [];
    if (file_exists($historyFile)) {
        $lines = file($historyFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $parts = explode(' ', trim($line), 4);
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
        <h1>アクセス状況・統計監視 (全期間)</h1>
        <p><strong>サーバー自身のIP（自動除外中）:</strong> <code><?php echo esc_html(IP_BLOCK_SERVER_MEIP); ?></code></p>
        
        <h2>📊 記録されているアクセス履歴</h2>
        <table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">
            <thead>
                <tr>
                    <th>IPアドレス</th>
                    <th>総アクセス回数</th>
                    <th>最終アクセス日時</th>
                    <th>直近アクセス先</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($active_accesses)): ?>
                    <tr><td colspan="4">現在記録されている外部のアクセスはありません。</td></tr>
                <?php else: ?>
                    <?php foreach ($active_accesses as $acc): ?>
                        <tr>
                            <td><code><?php echo esc_html($acc['ip']); ?></code></td>
                            <td><?php echo (int)$acc['count']; ?> 回</td>
                            <td><?php echo esc_html(date('Y-m-d H:i:s', (int)$acc['timestamp'])); ?></td>
                            <td><small><?php echo esc_html($acc['lastfile']); ?></small></td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
    <?php
}

// 2. ブロックリスト設定画面
function ip_block_blacklist_page_html() {
    if (!current_user_can('manage_options')) return;
    $blockFile = IP_BLOCK_DATA_DIR . '.block.env';

    if (isset($_POST['ip_block_submit'])) {
        check_admin_referer('ip_block_blacklist_nonce');
        if (isset($_POST['block_content'])) {
            file_put_contents($blockFile, sanitize_textarea_field(wp_unslash($_POST['block_content'])));
            echo '<div class="updated"><p><strong>ブロックリストを保存しました！</strong></p></div>';
        }
    }
    $block_data = file_exists($blockFile) ? file_get_contents($blockFile) : '';
    ?>
    <div class="wrap">
        <h1>🚫 ブロックリスト設定 (.block.env)</h1>
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

// 3. ホワイトリスト設定画面
function ip_block_whitelist_page_html() {
    if (!current_user_can('manage_options')) return;
    $whiteFile = IP_BLOCK_DATA_DIR . '.white.env';

    if (isset($_POST['ip_block_submit'])) {
        check_admin_referer('ip_block_whitelist_nonce');
        if (isset($_POST['white_content'])) {
            file_put_contents($whiteFile, sanitize_textarea_field(wp_unslash($_POST['white_content'])));
            echo '<div class="updated"><p><strong>ホワイトリストを保存しました！</strong></p></div>';
        }
    }
    $white_data = file_exists($whiteFile) ? file_get_contents($whiteFile) : '';
    ?>
    <div class="wrap">
        <h1>⚪ ホワイトリスト設定 (.white.env)</h1>
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

// 4. 例外パス設定画面
function ip_block_exceptions_page_html() {
    if (!current_user_can('manage_options')) return;
    $exceptionFile = IP_BLOCK_DATA_DIR . '.exception.env';

    if (isset($_POST['ip_block_submit'])) {
        check_admin_referer('ip_block_exceptions_nonce');
        if (isset($_POST['exception_content'])) {
            file_put_contents($exceptionFile, sanitize_textarea_field(wp_unslash($_POST['exception_content'])));
            echo '<div class="updated"><p><strong>例外パス設定を保存しました！</strong></p></div>';
        }
    }
    $exception_data = file_exists($exceptionFile) ? file_get_contents($exceptionFile) : '';
    ?>
    <div class="wrap">
        <h1>⏩ 例外パス設定 (.exception.env)</h1>
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