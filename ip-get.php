<?php
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'meip' => $_SERVER['REMOTE_ADDR']
]);