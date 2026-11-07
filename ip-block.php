<?php
/**
 * Plugin Name: IP Block & Rate Limiter Manager
 * Plugin URI:  https://github.com/utakeuchigames/ip-block
 * Description: 高度なIPブロック、例外パス、レートリミット監視および管理画面機能を提供するセキュリティプラグインです。
 * Version:     1.2.0
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
 * サーバー自身のIP（meip）をキャッシュ付きで取得
 */
function get_server_meip() {
    $cached_ip = get_transient('ip_block_server_meip');
    if ($cached_ip !== false) {
        return $cached_ip;
    }

    $url = rest_url() ? home_url('/wp-content/plugins/ip-block/ip-get.php') : ('http://' . ($_SERVER['SERVER_NAME'] ?? 'localhost') . '/wp-content/plugins/ip-block/ip-get.php');
    
    $response = wp_remote_get($url, ['timeout' => 2]);
    if (!is_wp_error($response)) {
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        if (isset($data['meip']) && !empty($data['meip'])) {
            $meip = $data['meip'];
            set_transient('ip_block_server_meip', $meip, HOUR_IN_SECONDS);
            return $meip;
        }
    }

    $fallback_ip = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname());
    return $fallback_ip;
}

/**
 * 設定ファイルから「#/ Clients can configure settings from here.」より下の有効なルールだけを抽出する関数
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
    $start_reading = !$has_marker; // マーカーがなければ最初から全て読む

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (!$start_reading) {
            if (strpos($trimmed, '#/ Clients can configure settings from here.') !== false) {
                $start_reading = true;
            }
            continue;
        }

        // 空行やコメント行はスキップ
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
    $meip = get_server_meip();
    if ($ip === $meip) {
        return true;
    }

    $whiteFile = URL_ROOT . '.white.env';
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
    $blockFile = URL_ROOT . '.block.env';
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
    $meip = get_server_meip();
    if ($ip === $meip) {
        return;
    }

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        header('HTTP/1.1 403 Forbidden');
        if (file_exists(URL_ROOT . 'error/403.html')) {
            require URL_ROOT . 'error/403.html';
        } else {
            echo "403 Forbidden";
        }
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

    header('HTTP/1.1 403 Forbidden');
    if (file_exists(URL_ROOT . 'error/403.html')) {
        require URL_ROOT . 'error/403.html';
    } else {
        echo "403 Forbidden";
    }
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
        header('HTTP/1.1 403 Forbidden');
        if (file_exists(URL_ROOT . 'error/403.html')) {
            require URL_ROOT . 'error/403.html';
        } else {
            echo "403 Forbidden";
        }
        exit;
    }

    // === 例外パス（スキップ対象）のチェック ===
    $exceptionFile = URL_ROOT . '.exception.env';
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

    // === レートリミット処理 ===
    $currentTime = microtime(true);
    $limitCount = 5;       
    $timeWindow = 1.0;     
    $envFile = URL_ROOT . '.access.env';

    if (!file_exists($envFile)) {
        file_put_contents($envFile, "");
    }

    $fp = fopen($envFile, 'r+');
    if (!flock($fp, LOCK_EX)) {
        exit("Server busy.");
    }

    $clientData = null;
    $otherData = [];

    while (($line = fgets($fp)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        
        $parts = explode(' ', $line, 4);
        if (count($parts) < 4) continue;
        
        list($ip, $timestamp, $count, $lastfile) = $parts;
        $timestamp = (float)$timestamp;
        $count = (int)$count;
        
        if ($ip === $clientIp) {
            $clientData = ['timestamp' => $timestamp, 'count' => $count, 'lastfile' => $lastfile];
        } else {
            if (($currentTime - $timestamp) < 60.0) {
                $otherData[] = "{$ip} {$timestamp} {$count} {$lastfile}";
            }
        }
    }

    if ($clientData !== null) {
        if (($currentTime - $clientData['timestamp']) < $timeWindow) {
            if ($clientData['count'] >= $limitCount) {
                flock($fp, LOCK_UN);
                fclose($fp);
                addBlockedIp($clientIp, URL_ROOT . '.block.env');
                exit;
            }
            $newCount = $clientData['count'] + 1;
            $newTimestamp = $clientData['timestamp'];
        } else {
            $newCount = 1;
            $newTimestamp = $currentTime;
        }
    } else {
        $newCount = 1;
        $newTimestamp = $currentTime;
    }
    
    $lastfile = $_SERVER['REQUEST_URI'];
    $otherData[] = "{$clientIp} {$newTimestamp} {$newCount} {$lastfile}";

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, implode("\n", $otherData) . "\n");

    flock($fp, LOCK_UN);
    fclose($fp);
    
    $accesscheck = true;
});

// 3. WordPress管理画面の設定メニュー追加
add_action('admin_menu', function() {
    add_menu_page(
        'IP Block 管理',
        'IP Block',
        'manage_options',
        'ip-block-manage',
        'ip_block_settings_page_html',
        'dashicons-shield',
        80
    );
});

// 管理画面のHTML描画
function ip_block_settings_page_html() {
    if (!current_user_can('manage_options')) {
        return;
    }

    $blockFile = URL_ROOT . '.block.env';
    $exceptionFile = URL_ROOT . '.exception.env';
    $whiteFile = URL_ROOT . '.white.env';
    $accessFile = URL_ROOT . '.access.env';

    if (isset($_POST['ip_block_submit'])) {
        check_admin_referer('ip_block_manage_nonce');
        
        if (isset($_POST['block_content'])) {
            file_put_contents($blockFile, sanitize_textarea_field(wp_unslash($_POST['block_content'])));
        }
        if (isset($_POST['exception_content'])) {
            file_put_contents($exceptionFile, sanitize_textarea_field(wp_unslash($_POST['exception_content'])));
        }
        if (isset($_POST['white_content'])) {
            file_put_contents($whiteFile, sanitize_textarea_field(wp_unslash($_POST['white_content'])));
        }
        echo '<div class="updated"><p><strong>設定を保存しました！</strong></p></div>';
    }

    $block_data = file_exists($blockFile) ? file_get_contents($blockFile) : '';
    $exception_data = file_exists($exceptionFile) ? file_get_contents($exceptionFile) : '';
    $white_data = file_exists($whiteFile) ? file_get_contents($whiteFile) : '';

    $current_meip = get_server_meip();

    $active_accesses = [];
    if (file_exists($accessFile)) {
        $lines = file($accessFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $now = microtime(true);
        foreach ($lines as $line) {
            $parts = explode(' ', trim($line), 4);
            if (count($parts) >= 4) {
                list($ip, $timestamp, $count, $lastfile) = $parts;
                
                // サーバー自身（meip）のアクセスログは管理画面のリストに表示させない（隠す）
                if ($ip === $current_meip) {
                    continue;
                }

                $timestamp = (float)$timestamp;
                $count = (int)$count;
                
                $elapsed = $now - $timestamp;
                if ($elapsed < 0) $elapsed = 0.001;

                $active_accesses[] = [
                    'ip' => $ip,
                    'timestamp' => $timestamp,
                    'count' => $count,
                    'elapsed' => $elapsed,
                    'avg_rate' => $count / max(($now - ($timestamp - $elapsed)), 1.0),
                    'lastfile' => $lastfile
                ];
            }
        }
    }
    ?>
    <div class="wrap">
        <h1>IP Block & アクセス監視管理</h1>
        <p><strong>サーバー自身のIP（自動除外中）:</strong> <code><?php echo esc_html($current_meip); ?></code></p>
        
        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 400px;">
                <form method="post" action="">
                    <?php wp_nonce_field('ip_block_manage_nonce'); ?>
                    
                    <h2>🚫 ブロックリスト (.block.env)</h2>
                    <p class="description"><code>#/ Clients can configure settings from here.</code> より下にIPやCIDRを記述してください。</p>
                    <textarea name="block_content" rows="6" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($block_data); ?></textarea>

                    <h2>⚪ ホワイトリスト (.white.env)</h2>
                    <p class="description"><code>#/ Clients can configure settings from here.</code> より下にIPやCIDRを記述してください。</p>
                    <textarea name="white_content" rows="6" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($white_data); ?></textarea>

                    <h2>⏩ 例外パス (.exception.env)</h2>
                    <textarea name="exception_content" rows="6" style="width: 100%; font-family: monospace;"><?php echo esc_textarea($exception_data); ?></textarea>

                    <p style="margin-top: 15px;">
                        <?php submit_button('設定を保存する', 'primary', 'ip_block_submit', false); ?>
                    </p>
                </form>
            </div>

            <div style="flex: 1; min-width: 450px;">
                <h2>📊 現在のアクセス状況・統計監視</h2>
                <table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">
                    <thead>
                        <tr>
                            <th>IPアドレス</th>
                            <th>アクセス回数</th>
                            <th>1秒平均件数</th>
                            <th>直近アクセス先</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($active_accesses)): ?>
                            <tr><td colspan="4">現在記録されている外部のアクティブなアクセスはありません。</td></tr>
                        <?php else: ?>
                            <?php foreach ($active_accesses as $acc): ?>
                                <tr>
                                    <td><code><?php echo esc_html($acc['ip']); ?></code></td>
                                    <td><?php echo (int)$acc['count']; ?> 回</td>
                                    <td><?php echo number_format($acc['count'] / max(($acc['elapsed']), 0.1), 2); ?> 回/秒</td>
                                    <td><small><?php echo esc_html($acc['lastfile']); ?></small></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php
}