# jwt
A simple library of JWT

## Installation

To install jwt run the command:

    composer require worldxyj/jwt


## Quick start

```php
use Worldxyj\Jwt;

$jwt = new Jwt('your own secret');

$payload = [
    'name' => 'worldxyj/jwt',
    'des' => '一个简单的JWT库'
];

$reponseDefault = $jwt->getToken($payload);// 默认过期时间1天

$reponseExp = $jwt->getTokenWithExp($payload, 3600 * 24);// 自定义过期时间

$res = $jwt->verifyToken($reponseDefault['data']);// 验证token

if($res['errcode'] == 0){
    $payload = $res['data'];
    echo '验证通过';
}
```