<?php
header('Content-Type: application/json');
echo json_encode([
    'php'    => PHP_VERSION,
    'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'nginx',
    'time'   => date('c'),
]);
