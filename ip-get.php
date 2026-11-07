<?php
header('Content-Type: application/json; charset=utf8');
echo json_encode(['meip' => $_SERVER["REMOTE_ADDR']]);