# php-radius
PHP based Radius server

Before using it, Please include the PHP socket extension (php_sockets.dll or php_sockets.so)
```php
$config = [
  'serverip' => '0.0.0.0',
  'serverport' => 1812,
  'secret' => 'secret',
  'receive_buffer' => 65535,
  'auth_method' => 'json',
  'debug' => RADIUS_DEBUG,
];
```

How to use ?
```
php server.php
```
