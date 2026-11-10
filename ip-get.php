<?php
header('Content-Type: application/json; charset=utf8');
$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? '127.0.0.1';
echo json_encode([
    'ip' => $ip
]);