<?php
    const RADIUS_SERVER_BASE = __DIR__;
    const DEBUG = false;
    
    define("RADIUS_OFF", 0);
    define("RADIUS_BASIC", 1);
    define("RADIUS_CONNECTION", 2);
    define("RADIUS_INFO", 3);
    define("RADIUS_DEBUG", 4);
    
    $config = [
        'serverip' => '0.0.0.0',
        'serverport' => 1812,
        'secret' => 'secret',
        'receive_buffer' => 65535,
        'auth_method' => 'json',
        'debug' => RADIUS_DEBUG,
    ];
    
    require_once __DIR__.'/class/radius.php';
    require_once __DIR__.'/class/json.php';
    require_once __DIR__.'/class/auth.php';
    
    $radius = new \server\RadiusServer();
    $radius->debugLevel = $config['debug'];
    $radius->load_dictionary();
    $radius->reverse_dictionary();
    $radius->initialize();
    $radius->radius_run($config);
