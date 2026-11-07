<?php
/**
 * Plugin Name: IP Block
 * Plugin URI:  https://github.com/utakeuchigames/ip-block
 * Description: 特定のIPアドレスからのアクセスをブロックするセキュリティプラグインです。
 * Version:     1.0.0
 * Author:      utakeuchigames
 * Author URI:  https://github.com/utakeuchigames
 * License:     GPL2
 * Text Domain: ip-block
 */

// セキュリティ対策：WordPressを介さない直接アクセスをブロック
if (!defined('ABSPATH') ) {
    exit;
}

/**
 * YahnisElsts/plugin-update-checker の組み込み
 * ※ プラグインのフォルダ内にライブラリ（plugin-update-checker）を配置している前提のパスやで
 */
if (file_exists(__DIR__ . '/plugin-update-checker/plugin-update-checker.php')) {
    require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';
    
    use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

    $myUpdateChecker = PucFactory::buildUpdateChecker(
        'https://github.com/utakeuchigames/ip-block',
        __FILE__,
        'ip-block'
    );

    // 必要に応じてブランチを指定（デフォルトはmain/master）
    $myUpdateChecker->setBranch('main');
}